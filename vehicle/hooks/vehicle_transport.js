// 仅用于授权测试。 Full vehicle bundle uses the host-side evidence stream.
import { createBufferedTransport } from './buffered_transport.js';
import { setTransport } from './vscan_runtime.js';

const transport = createBufferedTransport();
setTransport(transport);
rpc.exports.vscanFlush = transport.close;
