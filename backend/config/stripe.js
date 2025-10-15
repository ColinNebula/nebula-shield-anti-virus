require('dotenv').config({ path: require('path').join(__dirname, '..', '.env') });

const stripeKey = process.env.STRIPE_SECRET_KEY;
if (!stripeKey) {
  console.error('❌ STRIPE_SECRET_KEY not found in environment variables');
  throw new Error('STRIPE_SECRET_KEY is required');
}

const stripe = require('stripe')(stripeKey);
const { sendEmail, emailTemplates } = require('./email');

// Create Stripe checkout session
const createStripeCheckoutSession = async (userId, userEmail, userName) => {
  try {
    const session = await stripe.checkout.sessions.create({
      payment_method_types: ['card'],
      line_items: [
        {
          price_data: {
            currency: 'usd',
            product_data: {
              name: 'Nebula Shield Premium (Annual)',
              description: 'Full access to premium features for 1 year',
              images: ['https://your-domain.com/logo.png'],
            },
            unit_amount: Math.round(parseFloat(process.env.PREMIUM_PRICE_USD || 49) * 100), // Amount in cents
          },
          quantity: 1,
        },
      ],
      mode: 'payment',
      success_url: `${process.env.APP_URL}/payment/success?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${process.env.APP_URL}/payment/cancel`,
      customer_email: userEmail,
      client_reference_id: userId.toString(),
      metadata: {
        userId: userId.toString(),
        userName: userName,
        plan: 'premium-annual'
      }
    });

    return {
      success: true,
      sessionId: session.id,
      url: session.url
    };
  } catch (error) {
    console.error('Stripe checkout error:', error);
    return {
      success: false,
      error: error.message
    };
  }
};

// Verify Stripe payment
const verifyStripePayment = async (sessionId) => {
  try {
    const session = await stripe.checkout.sessions.retrieve(sessionId);
    
    if (session.payment_status === 'paid') {
      return {
        success: true,
        userId: parseInt(session.client_reference_id),
        amount: (session.amount_total / 100).toFixed(2),
        paymentMethod: 'Stripe',
        orderId: session.payment_intent
      };
    }
    
    return {
      success: false,
      error: 'Payment not completed'
    };
  } catch (error) {
    console.error('Stripe verification error:', error);
    return {
      success: false,
      error: error.message
    };
  }
};

// Handle Stripe webhook
const handleStripeWebhook = async (req, res) => {
  const sig = req.headers['stripe-signature'];
  let event;

  try {
    event = stripe.webhooks.constructEvent(
      req.body,
      sig,
      process.env.STRIPE_WEBHOOK_SECRET
    );
  } catch (err) {
    console.error('Webhook signature verification failed:', err.message);
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }

  // Handle the event
  switch (event.type) {
    case 'checkout.session.completed':
      const session = event.data.object;
      console.log('Payment successful:', session.id);
      // Upgrade user account logic here
      break;
    
    case 'payment_intent.payment_failed':
      const failedPayment = event.data.object;
      console.log('Payment failed:', failedPayment.id);
      // Send failure email
      break;
    
    default:
      console.log(`Unhandled event type ${event.type}`);
  }

  res.json({ received: true });
};

module.exports = {
  createStripeCheckoutSession,
  verifyStripePayment,
  handleStripeWebhook
};
