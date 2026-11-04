// Authorized tests only. One Java runtime per process avoids concurrent teardown.
import './java_bootstrap.js';
import './vehicle_transport.js';
import './hook_vhal.js';
import './hook_privacy.js';
import './hook_egress.js';
import './ssl_pinning_bypass.js';
