// Authorized tests only. One Java runtime per process avoids concurrent teardown.
import './java_bootstrap.js';
import './vehicle_transport.js';
import './hook_vhal.js';
import './hook_privacy.js';
import './hook_classload.js';
import './hook_egress.js';
import './ssl_pinning_bypass.js';
import { armVehicleTls } from './hook_vehicle_tls.js';

// 明文通道必须在 Java 就绪后装配（两个模块都是 main() 不自执行，
// side-effect import 会在 globalThis.Java 赋值前求值并 ReferenceError）。
Java.perform(armVehicleTls);
