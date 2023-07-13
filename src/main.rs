use std::time::Duration;

const USB_VID_AMLOGIC: u16 = 0x1b8e;
const USB_PID_S905X3: u16 = 0xc003;
const USB_PID_S905X4: u16 = 0xc004;

/* Request types - just one per direction */
// see https://vovkos.github.io/doxyrest/samples/libusb-sphinxdoc/enum_libusb_endpoint_direction.html#doxid-group-libusb-desc-1ga86c880af878493aa8f805c2aba654b8b
// IN
const REQ_TYPE_AMLIN: u8 = 0xc0;
// OUT
const REQ_TYPE_AMLOUT: u8 = 0x40;

/* Actual commands */
const REQ_READ_MEM: u8 = 0x02;

const REQ_IDENTIFY_HOST: u8 = 0x20;

const REQ_TPL_CMD: u8 = 0x30;
const REQ_PASSWORD: u8 = 0x35;
const REQ_NOP: u8 = 0x36;

/* Memory addresses */
// This is on a TV box based on S905X4
const FB_ADDR: u32 = 0x7f80_0000;
// from https://dn.odroid.com/S905/DataSheet/S905_Public_Datasheet_V1.1.4.pdf
const SYS_AHB_BASE: u32 = 0xC800_0000;
const CHIP_ID_ADDR: u32 = SYS_AHB_BASE + 0x0001_3c24;

fn int_to_bool_str(v: u8) -> &'static str {
    match v {
        1 => "yes",
        _ => "no",
    }
}

enum Command {
    Nop,
    Info,
    ReadMem,
    Password,
    Fastboot,
}

type Handle = rusb::DeviceHandle<rusb::GlobalContext>;

fn nop(handle: &Handle, timeout: Duration) {
    println!("nop");

    let buf: [u8; 0] = [0; 0];
    let r = handle.write_control(REQ_TYPE_AMLOUT, REQ_NOP, 0x0, 0x0, &buf, timeout);
    match r {
        Ok(_) => println!("Ok"),
        Err(_) => println!("Nope"),
    }
}

fn info(handle: &Handle, timeout: Duration) {
    println!("read information");
    let mut buf: [u8; 8] = [0; 8];
    match handle.read_control(
        REQ_TYPE_AMLIN,
        REQ_IDENTIFY_HOST,
        0x0,
        0x0,
        &mut buf,
        timeout,
    ) {
        Ok(_) => {
            println!("ROM version:   {}.{}", buf[0], buf[1]);
            println!("Stage version: {}.{}", buf[2], buf[3]);
            println!("Need password: {}", int_to_bool_str(buf[4]));
            println!("Password OK:   {}", int_to_bool_str(buf[5]));
        }
        Err(e) => println!("chip_id err: {e:?}"),
    }
    // FIXME: broken, should work though? See pyamlboot PROTOCOL.md
    if false {
        read_mem(handle, timeout, CHIP_ID_ADDR, 12).unwrap();
    }
}

// We can read max. 64 bytes at a time.
fn read_mem(handle: &Handle, timeout: Duration, addr: u32, size: u8) -> Result<(), &'static str> {
    let addr_l = addr as u16;
    let addr_h = (addr >> 16) as u16;
    println!("read memory @{addr_h:04x}{addr_l:04x}");
    if size > 64 {
        return Err("Memory read size is 64 max");
    }
    let mut buf = vec![0; size as usize];
    match handle.read_control(
        REQ_TYPE_AMLIN,
        REQ_READ_MEM,
        addr_h,
        addr_l,
        &mut buf,
        timeout,
    ) {
        Ok(_) => {
            println!("read_mem: {buf:02x?}");
        }
        Err(e) => println!("read_mem err: {e:?}"),
    }
    Ok(())
}

// Just for reference; untested as per pyamlboot
fn password(handle: &Handle, timeout: Duration) {
    println!("password");
    // password size is 64 bytes
    let buf: [u8; 64] = [0; 64];
    let r = handle.write_control(REQ_TYPE_AMLOUT, REQ_PASSWORD, 0x0, 0x0, &buf, timeout);
    println!("{r:?}");
}

// The command needs 0-byte termination, hence CString.
fn tpl_cmd(handle: &Handle, timeout: Duration, cmd: &str) {
    println!("tpl_cmd {cmd}");
    let cmd = std::ffi::CString::new(cmd).expect("C sucks");
    let buf = cmd.as_bytes_with_nul();
    let res = handle.write_control(
        REQ_TYPE_AMLOUT,
        REQ_TPL_CMD,
        0,
        1, // aka sub code - always 1 though?
        buf,
        timeout,
    );
    println!("{res:?}");
}

fn main() {
    let cmd = Command::Info;

    println!("Searching for Amlogic USB devices...");
    for device in rusb::devices().unwrap().iter() {
        let device_desc = device.device_descriptor().unwrap();

        let vid = device_desc.vendor_id();
        let pid = device_desc.product_id();

        if vid == USB_VID_AMLOGIC && (pid == USB_PID_S905X3 || pid == USB_PID_S905X4) {
            let s_type = if pid == USB_PID_S905X3 {
                "S905X, S905X2 or S905X3"
            } else {
                "S905X4"
            };
            println!(
                "Found {vid:04x}:{pid:04x} ({s_type}) on bus {:03}, device {:03}",
                device.bus_number(),
                device.address(),
            );

            // TODO: Not sure if this is sensible, or whether to use different
            // timeouts per command...
            let timeout = Duration::from_millis(2500);
            let handle = device.open().expect("Error opening USB device {e:?}");

            // TODO: write_mem, toggle some GPIO / LED on VIM1
            match cmd {
                Command::Nop => {
                    nop(&handle, timeout);
                }
                Command::Info => {
                    info(&handle, timeout);
                    // CPU power states, p47
                    read_mem(&handle, timeout, 0xc810_00e0, 8).unwrap();
                }
                Command::ReadMem => {
                    read_mem(&handle, timeout, FB_ADDR, 64).unwrap();
                }
                Command::Password => {
                    password(&handle, timeout);
                }
                Command::Fastboot => {
                    tpl_cmd(&handle, timeout, "fastboot");
                }
            }
        }
    }
}