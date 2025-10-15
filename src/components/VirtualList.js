import React, { useRef, useEffect, useState, useCallback } from 'react';
import PropTypes from 'prop-types';
import './VirtualList.css';

/**
 * VirtualList Component
 * Efficiently renders large lists by only rendering visible items
 * 
 * @param {Array} items - Array of items to render
 * @param {Function} renderItem - Function to render each item (item, index) => ReactNode
 * @param {Number} itemHeight - Height of each item in pixels
 * @param {Number} overscan - Number of items to render outside visible area (default: 3)
 * @param {Number} height - Container height (default: 600px)
 * @param {String} className - Additional CSS class names
 * @param {Function} onLoadMore - Callback when scrolling near bottom (for infinite scroll)
 * @param {Boolean} loading - Whether data is currently loading
 * @param {Boolean} hasMore - Whether there are more items to load
 */
const VirtualList = ({
  items = [],
  renderItem,
  itemHeight = 60,
  overscan = 3,
  height = 600,
  className = '',
  onLoadMore = null,
  loading = false,
  hasMore = false,
}) => {
  const containerRef = useRef(null);
  const [scrollTop, setScrollTop] = useState(0);
  const [visibleRange, setVisibleRange] = useState({ start: 0, end: 0 });

  // Calculate visible range based on scroll position
  const calculateVisibleRange = useCallback(() => {
    if (!containerRef.current) return { start: 0, end: 0 };

    const scrollTop = containerRef.current.scrollTop;
    const viewportHeight = height;
    
    // Calculate which items are visible
    const startIndex = Math.max(0, Math.floor(scrollTop / itemHeight) - overscan);
    const endIndex = Math.min(
      items.length,
      Math.ceil((scrollTop + viewportHeight) / itemHeight) + overscan
    );

    return { start: startIndex, end: endIndex };
  }, [items.length, itemHeight, overscan, height]);

  // Handle scroll events
  const handleScroll = useCallback(() => {
    if (!containerRef.current) return;

    const newScrollTop = containerRef.current.scrollTop;
    setScrollTop(newScrollTop);

    // Update visible range
    const newRange = calculateVisibleRange();
    setVisibleRange(newRange);

    // Check if we need to load more items
    if (onLoadMore && hasMore && !loading) {
      const scrollHeight = containerRef.current.scrollHeight;
      const clientHeight = containerRef.current.clientHeight;
      const scrollBottom = scrollHeight - (newScrollTop + clientHeight);

      // Load more when within 200px of bottom
      if (scrollBottom < 200) {
        onLoadMore();
      }
    }
  }, [calculateVisibleRange, onLoadMore, hasMore, loading]);

  // Set up scroll listener with throttling
  useEffect(() => {
    const container = containerRef.current;
    if (!container) return;

    let rafId = null;
    const throttledScroll = () => {
      if (rafId) return;
      rafId = requestAnimationFrame(() => {
        handleScroll();
        rafId = null;
      });
    };

    container.addEventListener('scroll', throttledScroll, { passive: true });
    
    // Initial calculation
    handleScroll();

    return () => {
      container.removeEventListener('scroll', throttledScroll);
      if (rafId) {
        cancelAnimationFrame(rafId);
      }
    };
  }, [handleScroll]);

  // Recalculate on items change
  useEffect(() => {
    const newRange = calculateVisibleRange();
    setVisibleRange(newRange);
  }, [items.length, calculateVisibleRange]);

  // Calculate total height and visible items
  const totalHeight = items.length * itemHeight;
  const visibleItems = items.slice(visibleRange.start, visibleRange.end);
  const offsetY = visibleRange.start * itemHeight;

  return (
    <div 
      ref={containerRef}
      className={`virtual-list-container ${className}`}
      style={{ 
        height: `${height}px`,
        overflow: 'auto',
        position: 'relative'
      }}
    >
      {/* Spacer to maintain total height */}
      <div 
        className="virtual-list-spacer"
        style={{ height: `${totalHeight}px`, position: 'relative' }}
      >
        {/* Visible items container */}
        <div 
          className="virtual-list-content"
          style={{ 
            transform: `translateY(${offsetY}px)`,
            position: 'absolute',
            top: 0,
            left: 0,
            right: 0
          }}
        >
          {visibleItems.map((item, index) => (
            <div
              key={visibleRange.start + index}
              className="virtual-list-item"
              style={{ height: `${itemHeight}px` }}
            >
              {renderItem(item, visibleRange.start + index)}
            </div>
          ))}
        </div>
      </div>

      {/* Loading indicator */}
      {loading && (
        <div className="virtual-list-loading">
          <div className="spinner"></div>
          <span>Loading more...</span>
        </div>
      )}

      {/* Empty state */}
      {!loading && items.length === 0 && (
        <div className="virtual-list-empty">
          <p>No items to display</p>
        </div>
      )}
    </div>
  );
};

VirtualList.propTypes = {
  items: PropTypes.array.isRequired,
  renderItem: PropTypes.func.isRequired,
  itemHeight: PropTypes.number,
  overscan: PropTypes.number,
  height: PropTypes.number,
  className: PropTypes.string,
  onLoadMore: PropTypes.func,
  loading: PropTypes.bool,
  hasMore: PropTypes.bool,
};

export default VirtualList;
