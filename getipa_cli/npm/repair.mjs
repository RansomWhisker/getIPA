// getipa helper: read already-decrypted code pages out of a *running* app with Frida.
// Usage: node repair.mjs <bundle-id> '<json ranges>' [frida-host]
//   ranges = [{"module": "Client"|null, "off": <offset from module base>, "size": N}, ...]
// Prints a JSON array of base64 strings (same order). Read-only: nothing is modified on the device.
import frida from 'frida';

const [bid, rangesJson, host] = process.argv.slice(2);
const ranges = JSON.parse(rangesJson);
const mgr = frida.getDeviceManager();
const devId = process.env.GETIPA_DEVICE;   // set by getipa when several USB devices are attached
const dev = host ? await mgr.addRemoteDevice(host)
  : devId ? await mgr.getDeviceById(devId, 8000) : await frida.getUsbDevice({ timeout: 8000 });
const delay = Number(process.env.GETIPA_DELAY_MS ?? 3500);
const pid = await dev.spawn([bid]);
let session;
if (delay < 0) {
  session = await dev.attach(pid);        // read while still suspended: for apps that quit as soon as they run
} else {
  await dev.resume(pid);
  await new Promise(r => setTimeout(r, delay));   // let dyld map and the app settle
  session = await dev.attach(pid);
}
const src = `
  rpc.exports.read = function (r) {
    var m = r.module ? Process.getModuleByName(r.module) : Process.mainModule;
    return m.base.add(r.off).readByteArray(r.size);
  };`;
const script = await session.createScript(src);
await script.load();
const out = [];
for (const r of ranges) {
  const buf = await script.exports.read(r);
  out.push(Buffer.from(buf).toString('base64'));
}
console.log(JSON.stringify(out));
try { await dev.kill(pid); } catch (e) {}
process.exit(0);
