// getipa helper: print the Frida ids of connected USB iOS devices as a JSON array.
// Needed because getUsbDevice() / bagbak's default pick whichever USB device comes first,
// which is wrong when an Android phone is plugged in too.
import frida from 'frida';

const out = [];
for (const d of await frida.getDeviceManager().enumerateDevices()) {
  if (d.type !== 'usb') continue;
  try {
    const p = await d.querySystemParameters();
    if (p.os && p.os.id === 'ios') out.push(d.id);
  } catch (e) {}
}
console.log(JSON.stringify(out));
process.exit(0);
