/**
 * Bulk Operations Service
 * Handles batch processing of multiple operations
 */

const EventEmitter = require('events');

class BulkOperationsService extends EventEmitter {
  constructor() {
    super();
    this.operations = new Map();
    this.operationId = 0;
  }

  /**
   * Create a new bulk operation
   * @param {String} type - Operation type (scan, delete, restore, quarantine)
   * @param {Array} items - Items to process
   * @param {Object} options - Operation options
   */
  createOperation(type, items, options = {}) {
    const id = `bulk_${++this.operationId}_${Date.now()}`;
    
    const operation = {
      id,
      type,
      items: items.map((item, index) => ({
        id: `${id}_item_${index}`,
        data: item,
        status: 'pending', // pending, processing, completed, failed
        progress: 0,
        result: null,
        error: null
      })),
      status: 'pending',
      progress: 0,
      totalItems: items.length,
      completedItems: 0,
      failedItems: 0,
      startTime: null,
      endTime: null,
      options,
      results: {
        success: [],
        failed: []
      }
    };

    this.operations.set(id, operation);
    this.emit('operation:created', operation);
    
    return operation;
  }

  /**
   * Execute a bulk operation
   * @param {String} operationId - Operation ID
   * @param {Function} processor - Function to process each item
   */
  async executeOperation(operationId, processor) {
    const operation = this.operations.get(operationId);
    
    if (!operation) {
      throw new Error(`Operation ${operationId} not found`);
    }

    if (operation.status !== 'pending') {
      throw new Error(`Operation ${operationId} is already ${operation.status}`);
    }

    operation.status = 'processing';
    operation.startTime = Date.now();
    this.emit('operation:started', operation);

    try {
      // Process items in parallel with concurrency limit
      const concurrency = operation.options.concurrency || 5;
      const chunks = this.chunkArray(operation.items, concurrency);

      for (const chunk of chunks) {
        await Promise.all(
          chunk.map(async (item) => {
            try {
              item.status = 'processing';
              this.updateProgress(operation);

              const result = await processor(item.data, operation.options);
              
              item.status = 'completed';
              item.result = result;
              item.progress = 100;
              operation.completedItems++;
              operation.results.success.push({
                itemId: item.id,
                data: item.data,
                result
              });

              this.emit('item:completed', { operation, item });
            } catch (error) {
              item.status = 'failed';
              item.error = error.message;
              item.progress = 0;
              operation.failedItems++;
              operation.results.failed.push({
                itemId: item.id,
                data: item.data,
                error: error.message
              });

              this.emit('item:failed', { operation, item, error });
            }

            this.updateProgress(operation);
          })
        );
      }

      operation.status = 'completed';
      operation.endTime = Date.now();
      operation.progress = 100;
      
      this.emit('operation:completed', operation);
      
      return operation;
    } catch (error) {
      operation.status = 'failed';
      operation.endTime = Date.now();
      operation.error = error.message;
      
      this.emit('operation:failed', { operation, error });
      
      throw error;
    }
  }

  /**
   * Cancel a bulk operation
   */
  cancelOperation(operationId) {
    const operation = this.operations.get(operationId);
    
    if (!operation) {
      throw new Error(`Operation ${operationId} not found`);
    }

    if (operation.status === 'completed' || operation.status === 'failed') {
      throw new Error(`Operation ${operationId} is already ${operation.status}`);
    }

    operation.status = 'cancelled';
    operation.endTime = Date.now();
    
    // Mark pending items as cancelled
    operation.items.forEach(item => {
      if (item.status === 'pending') {
        item.status = 'cancelled';
      }
    });

    this.emit('operation:cancelled', operation);
    
    return operation;
  }

  /**
   * Get operation status
   */
  getOperation(operationId) {
    return this.operations.get(operationId);
  }

  /**
   * Get all operations
   */
  getAllOperations() {
    return Array.from(this.operations.values());
  }

  /**
   * Delete operation from history
   */
  deleteOperation(operationId) {
    const operation = this.operations.get(operationId);
    
    if (!operation) {
      throw new Error(`Operation ${operationId} not found`);
    }

    this.operations.delete(operationId);
    this.emit('operation:deleted', { operationId });
    
    return true;
  }

  /**
   * Update operation progress
   */
  updateProgress(operation) {
    const processed = operation.completedItems + operation.failedItems;
    operation.progress = Math.round((processed / operation.totalItems) * 100);
    
    this.emit('operation:progress', {
      id: operation.id,
      progress: operation.progress,
      completedItems: operation.completedItems,
      failedItems: operation.failedItems,
      totalItems: operation.totalItems
    });
  }

  /**
   * Split array into chunks
   */
  chunkArray(array, size) {
    const chunks = [];
    for (let i = 0; i < array.length; i += size) {
      chunks.push(array.slice(i, i + size));
    }
    return chunks;
  }

  /**
   * Clean up old operations
   */
  cleanup(maxAge = 24 * 60 * 60 * 1000) { // 24 hours
    const now = Date.now();
    let cleaned = 0;

    for (const [id, operation] of this.operations.entries()) {
      if (operation.endTime && (now - operation.endTime) > maxAge) {
        this.operations.delete(id);
        cleaned++;
      }
    }

    if (cleaned > 0) {
      this.emit('cleanup:completed', { cleaned });
    }

    return cleaned;
  }

  /**
   * Get operation statistics
   */
  getStatistics() {
    const operations = Array.from(this.operations.values());
    
    return {
      total: operations.length,
      pending: operations.filter(op => op.status === 'pending').length,
      processing: operations.filter(op => op.status === 'processing').length,
      completed: operations.filter(op => op.status === 'completed').length,
      failed: operations.filter(op => op.status === 'failed').length,
      cancelled: operations.filter(op => op.status === 'cancelled').length,
      totalItems: operations.reduce((sum, op) => sum + op.totalItems, 0),
      completedItems: operations.reduce((sum, op) => sum + op.completedItems, 0),
      failedItems: operations.reduce((sum, op) => sum + op.failedItems, 0),
      averageDuration: this.calculateAverageDuration(operations)
    };
  }

  /**
   * Calculate average duration
   */
  calculateAverageDuration(operations) {
    const completed = operations.filter(op => op.endTime && op.startTime);
    
    if (completed.length === 0) return 0;
    
    const totalDuration = completed.reduce((sum, op) => {
      return sum + (op.endTime - op.startTime);
    }, 0);
    
    return Math.round(totalDuration / completed.length);
  }

  /**
   * Export operation results
   */
  exportResults(operationId, format = 'json') {
    const operation = this.operations.get(operationId);
    
    if (!operation) {
      throw new Error(`Operation ${operationId} not found`);
    }

    const exportData = {
      id: operation.id,
      type: operation.type,
      status: operation.status,
      totalItems: operation.totalItems,
      completedItems: operation.completedItems,
      failedItems: operation.failedItems,
      startTime: operation.startTime,
      endTime: operation.endTime,
      duration: operation.endTime ? operation.endTime - operation.startTime : null,
      results: operation.results,
      exportedAt: Date.now()
    };

    if (format === 'json') {
      return JSON.stringify(exportData, null, 2);
    } else if (format === 'csv') {
      return this.convertToCSV(exportData);
    }

    return exportData;
  }

  /**
   * Convert results to CSV
   */
  convertToCSV(exportData) {
    const rows = [];
    
    // Header
    rows.push('Item ID,Status,Type,Result,Error');
    
    // Success items
    exportData.results.success.forEach(item => {
      rows.push(`${item.itemId},Success,${exportData.type},${JSON.stringify(item.result).replace(/,/g, ';')},`);
    });
    
    // Failed items
    exportData.results.failed.forEach(item => {
      rows.push(`${item.itemId},Failed,${exportData.type},,${item.error.replace(/,/g, ';')}`);
    });
    
    return rows.join('\n');
  }
}

// Singleton instance
const bulkOperationsService = new BulkOperationsService();

module.exports = bulkOperationsService;
