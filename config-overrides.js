/**
 * Webpack Bundle Analyzer Configuration
 * Creates visualizations of bundle size
 */

const { BundleAnalyzerPlugin } = require('webpack-bundle-analyzer');

module.exports = function override(config, env) {
  // Add bundle analyzer in production mode
  if (env === 'production') {
    config.plugins.push(
      new BundleAnalyzerPlugin({
        analyzerMode: 'static',
        reportFilename: 'bundle-report.html',
        openAnalyzer: false,
        generateStatsFile: true,
        statsFilename: 'bundle-stats.json',
      })
    );
  }

  // Optimize chunk splitting
  config.optimization = {
    ...config.optimization,
    splitChunks: {
      chunks: 'all',
      cacheGroups: {
        // Vendor chunk for node_modules
        vendor: {
          test: /[\\/]node_modules[\\/]/,
          name: 'vendors',
          priority: 10,
          reuseExistingChunk: true,
        },
        // React and friends
        react: {
          test: /[\\/]node_modules[\\/](react|react-dom|react-router-dom)[\\/]/,
          name: 'react-vendor',
          priority: 20,
          reuseExistingChunk: true,
        },
        // Material UI and Emotion
        mui: {
          test: /[\\/]node_modules[\\/](@mui|@emotion)[\\/]/,
          name: 'mui-vendor',
          priority: 15,
          reuseExistingChunk: true,
        },
        // Chart libraries
        charts: {
          test: /[\\/]node_modules[\\/](recharts|d3)[\\/]/,
          name: 'charts-vendor',
          priority: 15,
          reuseExistingChunk: true,
        },
        // Lucide icons
        icons: {
          test: /[\\/]node_modules[\\/]lucide-react[\\/]/,
          name: 'icons-vendor',
          priority: 15,
          reuseExistingChunk: true,
        },
        // Common code used by multiple chunks
        common: {
          minChunks: 2,
          priority: 5,
          reuseExistingChunk: true,
          enforce: true,
        },
      },
    },
    // Minimize runtime chunk
    runtimeChunk: {
      name: 'runtime',
    },
    // Better module IDs for caching
    moduleIds: 'deterministic',
  };

  // Add performance hints
  config.performance = {
    maxEntrypointSize: 512000, // 500 KB
    maxAssetSize: 512000, // 500 KB
    hints: env === 'production' ? 'warning' : false,
  };

  return config;
};
