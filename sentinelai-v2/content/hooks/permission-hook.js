/**
 * SentinelAI v2.0 — Hook: Permission API Monitoring
 * Detects camera/microphone/geolocation abuse via Permissions API.
 */
(function() {
  'use strict';
  if (window.__sentinel_permission_hooked) return;
  window.__sentinel_permission_hooked = true;

  // Hook navigator.mediaDevices.getUserMedia (camera/mic)
  if (navigator.mediaDevices && navigator.mediaDevices.getUserMedia) {
    const originalGetUserMedia = navigator.mediaDevices.getUserMedia.bind(navigator.mediaDevices);
    navigator.mediaDevices.getUserMedia = function(constraints) {
      const event = {
        hook: 'permission',
        timestamp: Date.now(),
        data: {
          action: 'getUserMedia',
          audio: !!(constraints && constraints.audio),
          video: !!(constraints && constraints.video),
          constraints: JSON.stringify(constraints || {}).substring(0, 300)
        }
      };
      window.dispatchEvent(new CustomEvent('__sentinel_hook', { detail: event }));
      return originalGetUserMedia(constraints);
    };
  }

  // Hook navigator.geolocation.getCurrentPosition
  if (navigator.geolocation) {
    const originalGetPosition = navigator.geolocation.getCurrentPosition.bind(navigator.geolocation);
    navigator.geolocation.getCurrentPosition = function(success, error, options) {
      const event = {
        hook: 'permission',
        timestamp: Date.now(),
        data: {
          action: 'geolocation',
          type: 'getCurrentPosition'
        }
      };
      window.dispatchEvent(new CustomEvent('__sentinel_hook', { detail: event }));
      return originalGetPosition(success, error, options);
    };

    const originalWatchPosition = navigator.geolocation.watchPosition.bind(navigator.geolocation);
    navigator.geolocation.watchPosition = function(success, error, options) {
      const event = {
        hook: 'permission',
        timestamp: Date.now(),
        data: {
          action: 'geolocation',
          type: 'watchPosition'
        }
      };
      window.dispatchEvent(new CustomEvent('__sentinel_hook', { detail: event }));
      return originalWatchPosition(success, error, options);
    };
  }

  // Hook Notification.requestPermission
  if (window.Notification && Notification.requestPermission) {
    const originalRequestPermission = Notification.requestPermission.bind(Notification);
    Notification.requestPermission = function(callback) {
      const event = {
        hook: 'permission',
        timestamp: Date.now(),
        data: {
          action: 'notification',
          type: 'requestPermission'
        }
      };
      window.dispatchEvent(new CustomEvent('__sentinel_hook', { detail: event }));
      return originalRequestPermission(callback);
    };
  }

  // Hook navigator.permissions.query
  if (navigator.permissions && navigator.permissions.query) {
    const originalQuery = navigator.permissions.query.bind(navigator.permissions);
    navigator.permissions.query = function(descriptor) {
      const event = {
        hook: 'permission',
        timestamp: Date.now(),
        data: {
          action: 'permissionQuery',
          name: descriptor?.name || 'unknown'
        }
      };
      window.dispatchEvent(new CustomEvent('__sentinel_hook', { detail: event }));
      return originalQuery(descriptor);
    };
  }
})();
