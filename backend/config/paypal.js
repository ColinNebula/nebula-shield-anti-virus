require('dotenv').config({ path: require('path').join(__dirname, '..', '.env') });
const paypal = require('@paypal/checkout-server-sdk');

// PayPal environment
function environment() {
  const clientId = process.env.PAYPAL_CLIENT_ID;
  const clientSecret = process.env.PAYPAL_CLIENT_SECRET;
  
  if (process.env.PAYPAL_MODE === 'live') {
    return new paypal.core.LiveEnvironment(clientId, clientSecret);
  } else {
    return new paypal.core.SandboxEnvironment(clientId, clientSecret);
  }
}

// PayPal client
function client() {
  return new paypal.core.PayPalHttpClient(environment());
}

// Create PayPal order
const createPayPalOrder = async (userId, userEmail, userName) => {
  const request = new paypal.orders.OrdersCreateRequest();
  request.prefer("return=representation");
  request.requestBody({
    intent: 'CAPTURE',
    purchase_units: [{
      description: 'Nebula Shield Premium (Annual Subscription)',
      amount: {
        currency_code: 'USD',
        value: process.env.PREMIUM_PRICE_USD || '49.00'
      },
      custom_id: userId.toString()
    }],
    application_context: {
      brand_name: 'Nebula Shield',
      landing_page: 'BILLING',
      user_action: 'PAY_NOW',
      return_url: `${process.env.APP_URL}/payment/paypal/success`,
      cancel_url: `${process.env.APP_URL}/payment/cancel`
    }
  });

  try {
    const order = await client().execute(request);
    return {
      success: true,
      orderId: order.result.id,
      approvalUrl: order.result.links.find(link => link.rel === 'approve').href
    };
  } catch (error) {
    console.error('PayPal order creation error:', error);
    return {
      success: false,
      error: error.message
    };
  }
};

// Capture PayPal payment
const capturePayPalPayment = async (orderId) => {
  const request = new paypal.orders.OrdersCaptureRequest(orderId);
  request.requestBody({});

  try {
    const capture = await client().execute(request);
    const captureData = capture.result;
    
    if (captureData.status === 'COMPLETED') {
      return {
        success: true,
        userId: parseInt(captureData.purchase_units[0].custom_id),
        amount: captureData.purchase_units[0].amount.value,
        paymentMethod: 'PayPal',
        orderId: captureData.id,
        transactionId: captureData.purchase_units[0].payments.captures[0].id
      };
    }
    
    return {
      success: false,
      error: 'Payment not completed'
    };
  } catch (error) {
    console.error('PayPal capture error:', error);
    return {
      success: false,
      error: error.message
    };
  }
};

// Verify PayPal payment
const verifyPayPalPayment = async (orderId) => {
  const request = new paypal.orders.OrdersGetRequest(orderId);

  try {
    const order = await client().execute(request);
    return {
      success: true,
      status: order.result.status,
      details: order.result
    };
  } catch (error) {
    console.error('PayPal verification error:', error);
    return {
      success: false,
      error: error.message
    };
  }
};

module.exports = {
  createPayPalOrder,
  capturePayPalPayment,
  verifyPayPalPayment
};
