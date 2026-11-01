// Authorized tests only. One Java runtime per process avoids concurrent teardown.
import './java_bootstrap.js';
import './hook_vhal.js';
import './hook_egress.js';
import './ssl_pinning_bypass.js';
