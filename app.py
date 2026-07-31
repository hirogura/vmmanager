#!/usr/bin/env python3
import libvirt
import os
import socket
import time
from xml.etree import ElementTree as ET
from flask import Flask, render_template, request, jsonify, redirect, url_for, flash

app = Flask(__name__)
app.secret_key = os.urandom(24)

LIBVIRT_URI = "qemu:///system"


@app.context_processor
def inject_vms():
    try:
        conn = get_conn()
        vms = []
        for dom_id in conn.listDomainsID():
            dom = conn.lookupByID(dom_id)
            vms.append(_vm_info(dom))
        for name in conn.listDefinedDomains():
            dom = conn.lookupByName(name)
            vms.append(_vm_info(dom))
        conn.close()
        vms.sort(key=lambda v: v["name"].lower())
        return {"sidebar_vms": vms}
    except Exception:
        return {"sidebar_vms": []}


def get_conn():
    return libvirt.open(LIBVIRT_URI)


@app.route("/")
def index():
    conn = get_conn()
    vms = []
    for dom_id in conn.listDomainsID():
        dom = conn.lookupByID(dom_id)
        vms.append(_vm_info(dom))
    for name in conn.listDefinedDomains():
        dom = conn.lookupByName(name)
        vms.append(_vm_info(dom))
    conn.close()
    return render_template("index.html", vms=vms)


def _vm_info(dom):
    info = dom.info()
    xml_str = dom.XMLDesc(0)
    root = ET.fromstring(xml_str)
    os_el = root.find(".//os/type")
    os_type_attr = os_el.get("type", "") if os_el is not None else ""
    machine = os_el.get("machine", "") if os_el is not None else ""
    return {
        "id": dom.ID() if dom.isActive() else None,
        "name": dom.name(),
        "state": "running" if dom.isActive() else "stopped",
        "vcpus": info[3],
        "memory_mb": info[2] // 1024,
        "domain_type": root.get("type", ""),
        "machine": machine,
    }


@app.route("/vm/<name>")
def vm_detail(name):
    conn = get_conn()
    try:
        dom = conn.lookupByName(name)
    except libvirt.libvirtError:
        flash(f"VM '{name}' が見つかりません", "error")
        conn.close()
        return redirect(url_for("index"))

    xml_str = dom.XMLDesc(0)
    root = ET.fromstring(xml_str)
    devices = _parse_devices(root)
    is_active = dom.isActive()

    os_el = root.find(".//os/type")
    loader_el = root.find(".//os/loader")
    video_el = root.find(".//video/model")
    tpm_el = root.find(".//tpm")

    os_info = {
        "domain_type": root.get("type", ""),
        "arch": os_el.get("arch", "") if os_el is not None else "",
        "machine": os_el.get("machine", "") if os_el is not None else "",
    }

    vm_config = {
        "uefi": loader_el is not None,
        "secure_boot": False,
        "tpm_enabled": tpm_el is not None,
        "video_model": video_el.get("type", "") if video_el is not None else "",
        "vnc_enabled": False,
        "vnc_port": "-1",
        "vnc_listen": "0.0.0.0",
        "spice_enabled": False,
        "spice_port": "-1",
        "spice_listen": "0.0.0.0",
        "sound_enabled": root.find(".//sound") is not None,
        "channel_spice": root.find(".//channel[@type='spicevmc']") is not None,
        "usb_tablet": root.find(".//input[@type='tablet']") is not None,
        "usb_redirector_1": False,
        "usb_redirector_2": False,
    }
    firmware_el = root.find(".//firmware")
    if firmware_el is not None:
        for feat in firmware_el.findall("feature"):
            if feat.get("name") == "secure-boot" and feat.get("enabled") == "yes":
                vm_config["secure_boot"] = True
                break
    redir_count = 0
    for rd in root.findall(".//redirdev"):
        if rd.get("type") == "spicevmc":
            redir_count += 1
            if redir_count == 1:
                vm_config["usb_redirector_1"] = True
            elif redir_count == 2:
                vm_config["usb_redirector_2"] = True
    for g in devices["graphics"]:
        if g["type"] == "vnc":
            vm_config["vnc_enabled"] = True
            vm_config["vnc_port"] = g.get("port", "-1")
            vm_config["vnc_listen"] = g.get("listen_address", g.get("listen", "0.0.0.0"))
        elif g["type"] == "spice":
            vm_config["spice_enabled"] = True
            vm_config["spice_port"] = g.get("port", "-1")
            vm_config["spice_listen"] = g.get("listen_address", g.get("listen", "0.0.0.0"))

    vfio_hostdevs = []
    try:
        for nd in conn.listAllNodeDevices(0):
            try:
                nd_xml = nd.XMLDesc(0)
                nd_root = ET.fromstring(nd_xml)
                driver_el = nd_root.find("driver")
                if driver_el is not None and driver_el.get("name") == "vfio-pci":
                    cap = nd_root.find("capability")
                    vendor_el = cap.find("vendor") if cap is not None else None
                    product_el = cap.find("product") if cap is not None else None
                    domain_el = cap.find("domain") if cap is not None else None
                    bus_el = cap.find("bus") if cap is not None else None
                    slot_el = cap.find("slot") if cap is not None else None
                    func_el = cap.find("function") if cap is not None else None
                    vfio_hostdevs.append({
                        "name": nd.name(),
                        "vendor_id": vendor_el.get("id", "") if vendor_el is not None else "",
                        "product_id": product_el.get("id", "") if product_el is not None else "",
                        "description": cap.get("id", "") if cap is not None else nd.name(),
                        "domain": domain_el.text if domain_el is not None else "0x0000",
                        "bus": bus_el.text if bus_el is not None else "",
                        "slot": slot_el.text if slot_el is not None else "",
                        "function": func_el.text if func_el is not None else "",
                    })
            except Exception:
                continue
    except Exception:
        pass

    networks = []
    for nname in conn.listNetworks():
        net = conn.networkLookupByName(nname)
        networks.append({"name": nname, "active": net.isActive()})

    host_info = {}
    try:
        info = conn.getInfo()
        host_info["max_vcpus"] = info[2]
        host_info["max_memory_mb"] = info[1]
    except Exception:
        pass

    conn.close()
    return render_template(
        "vm_detail.html",
        vm=_vm_info(dom),
        xml=xml_str,
        devices=devices,
        os_info=os_info,
        vm_config=vm_config,
        networks=networks,
        is_active=is_active,
        vfio_hostdevs=vfio_hostdevs,
        host_info=host_info,
    )


def _parse_devices(root):
    devices = {"disks": [], "graphics": [], "networks": [], "hostdevs": []}

    for disk in root.findall(".//disk"):
        d = {
            "type": disk.get("type", ""),
            "device": disk.get("device", "disk"),
            "target_dev": "",
            "target_bus": "",
            "source_file": "",
            "source_dev": "",
            "source_protocol": "",
            "source_name": "",
            "driver_type": "",
        }
        target = disk.find("target")
        if target is not None:
            d["target_dev"] = target.get("dev", "")
            d["target_bus"] = target.get("bus", "")
        source = disk.find("source")
        if source is not None:
            d["source_file"] = source.get("file", "")
            d["source_dev"] = source.get("dev", "")
            d["source_protocol"] = source.get("protocol", "")
            d["source_name"] = source.get("name", "")
        driver = disk.find("driver")
        if driver is not None:
            d["driver_type"] = driver.get("type", "")
        devices["disks"].append(d)

    for graphics in root.findall(".//graphics"):
        g = {
            "type": graphics.get("type", ""),
            "port": graphics.get("port", ""),
            "tlsPort": graphics.get("tlsPort", ""),
            "autoport": graphics.get("autoport", ""),
            "listen": graphics.get("listen", ""),
        }
        listen_el = graphics.find("listen")
        if listen_el is not None:
            g["listen_type"] = listen_el.get("type", "")
            g["listen_address"] = listen_el.get("address", "")
        devices["graphics"].append(g)

    for iface in root.findall(".//interface"):
        n = {
            "type": iface.get("type", ""),
            "mac": "",
            "source_network": "",
            "model": "",
        }
        mac = iface.find("mac")
        if mac is not None:
            n["mac"] = mac.get("address", "")
        source = iface.find("source")
        if source is not None:
            n["source_network"] = source.get("network", "") or source.get("bridge", "")
        model = iface.find("model")
        if model is not None:
            n["model"] = model.get("type", "")
        devices["networks"].append(n)

    for hostdev in root.findall(".//hostdev"):
        h = {"type": hostdev.get("type", ""), "mode": hostdev.get("mode", "")}
        source = hostdev.find("source")
        if source is not None:
            address = source.find("address")
            if address is not None:
                h["domain"] = address.get("domain", "")
                h["bus"] = address.get("bus", "")
                h["slot"] = address.get("slot", "")
                h["function"] = address.get("function", "")
        devices["hostdevs"].append(h)

    for hostdev in root.findall(".//hostdev"):
        if hostdev.get("type") == "usb":
            uh = {"vendor_id": "", "product_id": ""}
            source = hostdev.find("source")
            if source is not None:
                vendor = source.find("vendor")
                product = source.find("product")
                uh["vendor_id"] = vendor.get("id", "") if vendor is not None else ""
                uh["product_id"] = product.get("id", "") if product is not None else ""
            devices.setdefault("usb_hostdevs", []).append(uh)

    return devices


def _get_usb_devices():
    import subprocess
    usb_devices = []
    try:
        result = subprocess.run(
            ["lsusb"], capture_output=True, text=True, timeout=5
        )
        for line in result.stdout.strip().split("\n"):
            if not line.strip():
                continue
            parts = line.split()
            if len(parts) < 6:
                continue
            id_str = parts[5]
            if ":" not in id_str:
                continue
            vendor_id, product_id = id_str.split(":", 1)
            name = " ".join(parts[6:])
            bus = parts[1]
            dev = parts[3].rstrip(":")
            usb_devices.append({
                "vendor_id": vendor_id,
                "product_id": product_id,
                "name": name,
                "bus": bus,
                "device": dev,
                "label": f"{id_str} - {name} (Bus {bus}, Dev {dev})",
            })
    except Exception:
        pass
    return usb_devices


@app.route("/api/usb-devices")
def api_usb_devices():
    return jsonify(_get_usb_devices())


@app.route("/vm/<name>/edit", methods=["GET", "POST"])
def vm_edit(name):
    if request.method == "GET":
        return redirect(url_for("vm_detail", name=name))

    config = request.json
    config["name"] = name

    conn = get_conn()
    try:
        dom = conn.lookupByName(name)
    except libvirt.libvirtError:
        conn.close()
        return jsonify({"error": f"VM '{name}' が見つかりません"}), 404

    if dom.isActive():
        conn.close()
        return jsonify({"error": "VMを停止してから編集してください"}), 400

    config["uuid"] = dom.UUIDString()
    new_xml = _build_edit_xml(config)
    if new_xml is None:
        conn.close()
        return jsonify({"error": "XMLの生成に失敗しました"}), 400

    try:
        import subprocess, tempfile

        old_xml_str = dom.XMLDesc(0)
        old_root = ET.fromstring(old_xml_str)
        old_firmware_el = old_root.find(".//firmware")
        old_secure_boot = False
        if old_firmware_el is not None:
            for feat in old_firmware_el.findall("feature"):
                if feat.get("name") == "secure-boot" and feat.get("enabled") == "yes":
                    old_secure_boot = True
                    break

        new_uefi = config.get("uefi", False)
        new_secure_boot = config.get("secure_boot", False)

        if old_secure_boot != new_secure_boot:
            nvram_path = f"/var/lib/libvirt/qemu/nvram/{name}_VARS.fd"
            subprocess.run(["sudo", "rm", "-f", nvram_path], capture_output=True, timeout=5)

        with tempfile.NamedTemporaryFile(mode='w', suffix='.xml', delete=False) as f:
            f.write(new_xml)
            tmp_path = f.name
        r = subprocess.run(
            ["sudo", "virsh", "define", tmp_path],
            capture_output=True, text=True, timeout=10
        )
        subprocess.run(["sudo", "rm", "-f", tmp_path], capture_output=True, timeout=5)
        if r.returncode != 0:
            conn.close()
            return jsonify({"error": r.stderr.strip() or r.stdout.strip()}), 400
        conn.close()
        return jsonify({"success": True})
    except Exception as e:
        conn.close()
        return jsonify({"error": str(e)}), 400


def _build_edit_xml(config):
    name = config.get("name", "")
    domain_type = config.get("domain_type", "kvm")
    vcpus = int(config.get("vcpus", 2))
    memory_mb = int(config.get("memory_mb", 4096))
    memory_kb = memory_mb * 1024
    arch = config.get("arch", "x86_64")
    machine = config.get("machine", "pc-q35-10.2")
    uefi = config.get("uefi", False)

    vnc_enabled = config.get("vnc_enabled", True)
    vnc_port = config.get("vnc_port", "") or "-1"
    try:
        int(vnc_port)
    except (ValueError, TypeError):
        vnc_port = "-1"
    vnc_listen = config.get("vnc_listen", "") or "0.0.0.0"
    spice_enabled = config.get("spice_enabled", False)
    spice_port = config.get("spice_port", "") or "-1"
    try:
        int(spice_port)
    except (ValueError, TypeError):
        spice_port = "-1"
    spice_tls_port = config.get("spice_tls_port", "") or ""
    spice_listen = config.get("spice_listen", "") or "0.0.0.0"

    video_model = config.get("video_model", "")
    if not video_model:
        video_model = "qxl" if spice_enabled else "virtio"
    tpm_enabled = config.get("tpm_enabled", False)

    net_type = config.get("net_type", "network")
    net_source = config.get("net_source", "default")
    net_model = config.get("net_model", "virtio")

    existing_disks = config.get("existing_disks", [])
    disk_order = config.get("disk_order", [])
    new_disks = config.get("disks", [])
    iso_paths = config.get("iso_paths", [])
    hostdevs = config.get("hostdevs", [])
    existing_usbs = config.get("existing_usbs", [])
    usb_hostdevs = config.get("usb_hostdevs", [])
    boot_order = config.get("boot_order", [])

    lines = []
    lines.append(f'<domain type="{domain_type}">')
    lines.append(f"  <name>{name}</name>")
    uuid = config.get("uuid", "")
    if uuid:
        lines.append(f"  <uuid>{uuid}</uuid>")
    lines.append(f"  <memory unit='KiB'>{memory_kb}</memory>")
    lines.append(f"  <currentMemory unit='KiB'>{memory_kb}</currentMemory>")
    lines.append(f"  <vcpu placement='static'>{vcpus}</vcpu>")
    lines.append("  <cpu mode='host-passthrough' check='none'>")
    lines.append(f"    <topology sockets='1' dies='1' cores='{vcpus}' threads='1'/>")
    lines.append("  </cpu>")
    if uefi:
        secure_boot = config.get("secure_boot", False)
        if secure_boot:
            lines.append("  <os firmware='efi'>")
            lines.append(f"    <type arch='{arch}' machine='{machine}'>hvm</type>")
            lines.append("    <firmware>")
            lines.append("      <feature enabled='yes' name='enrolled-keys'/>")
            lines.append("      <feature enabled='yes' name='secure-boot'/>")
            lines.append("    </firmware>")
            lines.append("    <loader readonly='yes' secure='yes' type='pflash' format='raw'>/usr/share/OVMF/OVMF_CODE_4M.ms.fd</loader>")
            lines.append(f"    <nvram template='/usr/share/OVMF/OVMF_VARS_4M.ms.fd' templateFormat='raw' format='raw'>/var/lib/libvirt/qemu/nvram/{name}_VARS.fd</nvram>")
        else:
            lines.append("  <os firmware='efi'>")
            lines.append(f"    <type arch='{arch}' machine='{machine}'>hvm</type>")
            lines.append("    <firmware>")
            lines.append("      <feature enabled='no' name='enrolled-keys'/>")
            lines.append("      <feature enabled='no' name='secure-boot'/>")
            lines.append("    </firmware>")
            lines.append("    <loader readonly='yes' secure='no' type='pflash' stateless='yes' format='raw'>/usr/share/ovmf/OVMF.amdsev.fd</loader>")
        if boot_order:
            for dev in boot_order:
                lines.append(f"    <boot dev='{dev}'/>")
        else:
            lines.append("    <boot dev='hd'/>")
        lines.append("    <bootmenu enable='yes'/>")
    else:
        lines.append("  <os>")
        lines.append(f"    <type arch='{arch}' machine='{machine}'>hvm</type>")
        if boot_order:
            for dev in boot_order:
                lines.append(f"    <boot dev='{dev}'/>")
        else:
            lines.append("    <boot dev='hd'/>")
    lines.append("  </os>")
    lines.append("  <features><acpi/><apic/></features>")
    lines.append("  <clock offset='utc'/>")
    lines.append("  <devices>")

    if disk_order:
        disk_map = {ed['target_dev']: ed for ed in existing_disks if 'target_dev' in ed}
        reordered = []
        for item in disk_order:
            t = item.get('target', '')
            if t in disk_map:
                reordered.append(disk_map.pop(t))
        reordered.extend(disk_map.values())
        existing_disks = reordered

    for ed in existing_disks:
        lines.append(f"    <disk type='{ed['type']}' device='{ed['device']}'>")
        lines.append(f"      <driver name='qemu' type='{ed['driver_type']}'/>")
        if ed["type"] == "file" and ed["source_file"]:
            lines.append(f"      <source file='{ed['source_file']}'/>")
        elif ed["type"] == "block" and ed["source_dev"]:
            lines.append(f"      <source dev='{ed['source_dev']}'/>")
        elif ed["type"] == "volume":
            pool = ed.get("source_pool", "default")
            vol = ed.get("source_volume", "")
            lines.append(f"      <source pool='{pool}' volume='{vol}'/>")
        elif ed["type"] == "network":
            proto = ed.get("source_protocol", "iscsi")
            sname = ed.get("source_name", "")
            lines.append(f"      <source protocol='{proto}' name='{sname}'/>")
        target_dev = ed.get("target_dev", "vda")
        target_bus = ed.get("target_bus", "virtio")
        lines.append(f"      <target dev='{target_dev}' bus='{target_bus}'/>")
        if ed.get("readonly"):
            lines.append("      <readonly/>")
        lines.append("    </disk>")

    for nd in new_disks:
        dtype = nd.get("type", "")
        if dtype == "block_lun":
            lines.append("    <disk type='block' device='lun'>")
            lines.append(f"      <driver name='qemu' type='{nd.get('driver_type', 'raw')}'/>")
            lines.append(f"      <source dev='{nd.get('source_dev', '')}'/>")
            lines.append(f"      <target dev='{nd.get('target_dev', 'sdb')}' bus='scsi'/>")
            lines.append("    </disk>")
        elif dtype == "block":
            lines.append("    <disk type='block' device='disk'>")
            lines.append(f"      <driver name='qemu' type='{nd.get('driver_type', 'raw')}'/>")
            lines.append(f"      <source dev='{nd.get('source_dev', '')}'/>")
            lines.append(f"      <target dev='{nd.get('target_dev', 'vdb')}' bus='{nd.get('target_bus', 'virtio')}'/>")
            lines.append("    </disk>")
        elif dtype == "file":
            lines.append("    <disk type='file' device='disk'>")
            lines.append(f"      <driver name='qemu' type='{nd.get('driver_type', 'qcow2')}'/>")
            lines.append(f"      <source file='{nd.get('source_file', '')}'/>")
            lines.append(f"      <target dev='{nd.get('target_dev', 'vdb')}' bus='{nd.get('target_bus', 'virtio')}'/>")
            lines.append("    </disk>")

    iso_idx = 0
    for iso in iso_paths:
        if isinstance(iso, dict):
            iso_path = iso.get("path", "").strip()
            iso_target = iso.get("target", "").strip()
        else:
            iso_path = str(iso).strip()
            iso_target = ""
        if iso_path:
            dev = iso_target if iso_target else f"sd{chr(ord('c') + iso_idx)}"
            lines.append("    <disk type='file' device='cdrom'>")
            lines.append("      <driver name='qemu' type='raw'/>")
            lines.append(f"      <source file='{iso_path}'/>")
            lines.append(f"      <target dev='{dev}' bus='sata'/>")
            lines.append("      <readonly/>")
            lines.append("    </disk>")
            iso_idx += 1

    if vnc_enabled:
        lines.append(f"    <graphics type='vnc' port='{vnc_port}' autoport='yes' listen='{vnc_listen}'>")
        lines.append(f"      <listen type='address' address='{vnc_listen}'/>")
        lines.append("    </graphics>")

    if spice_enabled:
        spice_attrs = f"    <graphics type='spice' port='{spice_port}' autoport='yes' listen='{spice_listen}'"
        if spice_tls_port:
            spice_attrs += f" tlsPort='{spice_tls_port}'"
        spice_attrs += ">"
        lines.append(spice_attrs)
        lines.append(f"      <listen type='address' address='{spice_listen}'/>")
        lines.append("      <image compression='off'/>")
        lines.append("      <playback compression='on'/>")
        lines.append("      <streaming mode='filter'/>")
        lines.append("      <clipboard copypaste='yes'/>")
        lines.append("      <filetransfer enable='yes'/>")
        lines.append("    </graphics>")

    lines.append(f"    <interface type='{net_type}'>")
    if net_type == "network":
        lines.append(f"      <source network='{net_source}'/>")
    elif net_type == "bridge":
        lines.append(f"      <source bridge='{net_source}'/>")
    elif net_type == "direct":
        lines.append(f"      <source dev='{net_source}'/>")
    lines.append(f"      <model type='{net_model}'/>")
    lines.append("    </interface>")

    for hd in hostdevs:
        lines.append("    <hostdev mode='subsystem' type='pci' managed='yes'>")
        lines.append("      <source>")
        lines.append(f"        <address domain='{hd.get('domain', '0x0000')}' bus='{hd.get('bus', '0x00')}' slot='{hd.get('slot', '0x00')}' function='{hd.get('function', '0x0')}'/>")
        lines.append("      </source>")
        lines.append("    </hostdev>")

    for uhd in existing_usbs:
        lines.append("    <hostdev mode='subsystem' type='usb' managed='yes'>")
        lines.append("      <source>")
        lines.append(f"        <vendor id='{uhd['vendor_id']}'/>")
        lines.append(f"        <product id='{uhd['product_id']}'/>")
        lines.append("      </source>")
        lines.append("    </hostdev>")

    usb_hostdevs = config.get("usb_hostdevs", [])
    for uhd in usb_hostdevs:
        lines.append("    <hostdev mode='subsystem' type='usb' managed='yes'>")
        lines.append("      <source>")
        lines.append(f"        <vendor id='0x{uhd['vendor_id']}'/>")
        lines.append(f"        <product id='0x{uhd['product_id']}'/>")
        lines.append("      </source>")
        lines.append("    </hostdev>")

    lines.append("    <video>")
    if video_model == "qxl":
        lines.append("      <model type='qxl' ram='65536' vram='65536' vgamem='16384' heads='1'/>")
    elif video_model and video_model != "none":
        lines.append(f"      <model type='{video_model}' heads='1'/>")
    elif not video_model:
        lines.append("      <model type='virtio' heads='1'/>")
    lines.append("    </video>")

    if tpm_enabled:
        lines.append("    <tpm model='tpm-crb'>")
        lines.append("      <backend type='emulator'/>")
        lines.append("    </tpm>")

    sound_enabled = config.get("sound_enabled", False)
    channel_spice = config.get("channel_spice", False)
    usb_redirector_1 = config.get("usb_redirector_1", False)
    usb_redirector_2 = config.get("usb_redirector_2", False)

    if sound_enabled:
        lines.append("    <sound model='ich9'/>")

    if channel_spice:
        lines.append("    <channel type='spicevmc'>")
        lines.append("      <target type='virtio' name='com.redhat.spice.0'/>")
        lines.append("    </channel>")

    usb_tablet = config.get("usb_tablet", False)
    if usb_tablet:
        lines.append("    <input type='tablet' bus='usb'/>")

    if usb_redirector_1:
        lines.append("    <redirdev bus='usb' type='spicevmc'/>")
    if usb_redirector_2:
        lines.append("    <redirdev bus='usb' type='spicevmc'/>")

    has_scsi = any(nd.get("target_bus") == "scsi" or nd.get("type") == "block_lun" for nd in new_disks)
    if not has_scsi:
        for ed in existing_disks:
            if ed.get("target_bus") == "scsi":
                has_scsi = True
                break
    if has_scsi:
        lines.append("    <controller type='scsi' index='0' model='virtio-scsi'/>")

    lines.append("    <memballoon model='virtio'/>")
    lines.append("  </devices>")
    lines.append("  <seclabel type='dynamic' model='apparmor' relabel='yes'/>")
    lines.append("</domain>")

    return "\n".join(lines)


@app.route("/api/vm/<name>/action", methods=["POST"])
def vm_action(name):
    conn = get_conn()
    try:
        dom = conn.lookupByName(name)
    except libvirt.libvirtError:
        conn.close()
        return jsonify({"error": f"VM '{name}' が見つかりません"}), 404

    action = request.json.get("action")
    try:
        if action == "start":
            dom.create()
        elif action == "stop":
            dom.shutdown()
        elif action == "destroy":
            dom.destroy()
        elif action == "undefine":
            if dom.isActive():
                conn.close()
                return jsonify({"error": "先にVMを停止してください"}), 400

            delete_disk = request.json.get("delete_disk", False)
            disk_paths = []
            if delete_disk:
                xml_str = dom.XMLDesc(0)
                root = ET.fromstring(xml_str)
                for disk in root.findall(".//disk"):
                    device = disk.get("device", "disk")
                    if device == "cdrom":
                        continue
                    source = disk.find("source")
                    if source is None:
                        continue
                    path = source.get("file", "") or source.get("dev", "")
                    if not path:
                        pool_name = source.get("pool", "")
                        vol_name = source.get("volume", "")
                        if pool_name and vol_name:
                            try:
                                pool = conn.storagePoolLookupByName(pool_name)
                                vol = pool.storageVolLookupByName(vol_name)
                                path = vol.path()
                            except Exception:
                                pass
                    if path:
                        disk_paths.append(path)

            import subprocess
            try:
                subprocess.run(
                    ["sudo", "virsh", "undefine", name, "--nvram"],
                    capture_output=True, timeout=10, check=True
                )
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
                try:
                    dom.undefine()
                except libvirt.libvirtError as ue:
                    conn.close()
                    return jsonify({"error": str(ue)}), 400

            if delete_disk and disk_paths:
                for dp in disk_paths:
                    try:
                        subprocess.run(
                            ["sudo", "rm", "-f", dp],
                            capture_output=True, timeout=10
                        )
                    except Exception:
                        pass
                try:
                    nvram_path = f"/var/lib/libvirt/qemu/nvram/{name}_VARS.fd"
                    subprocess.run(
                        ["sudo", "rm", "-f", nvram_path],
                        capture_output=True, timeout=5
                    )
                except Exception:
                    pass
        elif action == "suspend":
            dom.suspend()
        elif action == "resume":
            dom.resume()
        elif action == "reboot":
            dom.reboot()
        elif action == "autostart_on":
            dom.setAutostart(1)
        elif action == "autostart_off":
            dom.setAutostart(0)
        elif action == "usb_attach":
            vendor_id = request.json.get("vendor_id", "")
            product_id = request.json.get("product_id", "")
            if not vendor_id or not product_id:
                result = {"error": "vendor_id と product_id が必要です"}
            else:
                if dom.isActive():
                    usb_xml = f"""<hostdev mode='subsystem' type='usb' managed='yes'>
      <source>
        <vendor id='0x{vendor_id}'/>
        <product id='0x{product_id}'/>
      </source>
    </hostdev>"""
                    try:
                        import subprocess, tempfile
                        with tempfile.NamedTemporaryFile(mode='w', suffix='.xml', delete=False) as f:
                            f.write(usb_xml)
                            tmp_path = f.name
                        r = subprocess.run(
                            ["sudo", "virsh", "attach-device", name, "--file", tmp_path],
                            capture_output=True, text=True, timeout=10
                        )
                        subprocess.run(["sudo", "rm", "-f", tmp_path], capture_output=True, timeout=5)
                        if r.returncode != 0:
                            result = {"error": r.stderr.strip() or r.stdout.strip()}
                    except (subprocess.TimeoutExpired, Exception) as e:
                        result = {"error": str(e)}
                else:
                    try:
                        xml_str = dom.XMLDesc(0)
                        root = ET.fromstring(xml_str)
                        devices_el = root.find(".//devices")
                        hostdev_el = ET.SubElement(devices_el, "hostdev")
                        hostdev_el.set("mode", "subsystem")
                        hostdev_el.set("type", "usb")
                        hostdev_el.set("managed", "yes")
                        source_el = ET.SubElement(hostdev_el, "source")
                        vendor_el = ET.SubElement(source_el, "vendor")
                        vendor_el.set("id", f"0x{vendor_id}")
                        product_el = ET.SubElement(source_el, "product")
                        product_el.set("id", f"0x{product_id}")
                        new_xml = ET.tostring(root, encoding="unicode")
                        conn.defineXML(new_xml)
                    except libvirt.libvirtError as e:
                        result = {"error": str(e)}
        elif action == "usb_detach":
            vendor_id = request.json.get("vendor_id", "")
            product_id = request.json.get("product_id", "")
            if not vendor_id or not product_id:
                result = {"error": "vendor_id と product_id が必要です"}
            else:
                if dom.isActive():
                    usb_xml = f"""<hostdev mode='subsystem' type='usb' managed='yes'>
      <source>
        <vendor id='0x{vendor_id}'/>
        <product id='0x{product_id}'/>
      </source>
    </hostdev>"""
                    try:
                        import subprocess, tempfile
                        with tempfile.NamedTemporaryFile(mode='w', suffix='.xml', delete=False) as f:
                            f.write(usb_xml)
                            tmp_path = f.name
                        r = subprocess.run(
                            ["sudo", "virsh", "detach-device", name, "--file", tmp_path],
                            capture_output=True, text=True, timeout=10
                        )
                        subprocess.run(["sudo", "rm", "-f", tmp_path], capture_output=True, timeout=5)
                        if r.returncode != 0:
                            result = {"error": r.stderr.strip() or r.stdout.strip()}
                    except (subprocess.TimeoutExpired, Exception) as e:
                        result = {"error": str(e)}
                else:
                    try:
                        xml_str = dom.XMLDesc(0)
                        root = ET.fromstring(xml_str)
                        devices_el = root.find(".//devices")
                        removed = False
                        for hd in root.findall(".//hostdev[@type='usb']"):
                            src = hd.find("source")
                            if src is not None:
                                v = src.find("vendor")
                                p = src.find("product")
                                if v is not None and p is not None:
                                    vid = v.get("id", "").replace("0x", "")
                                    pid = p.get("id", "").replace("0x", "")
                                    if vid == vendor_id and pid == product_id:
                                        devices_el.remove(hd)
                                        removed = True
                                        break
                        if not removed:
                            result = {"error": f"USBデバイス 0x{vendor_id}:0x{product_id} が見つかりません"}
                        else:
                            new_xml = ET.tostring(root, encoding="unicode")
                            conn.defineXML(new_xml)
                    except libvirt.libvirtError as e:
                        result = {"error": str(e)}
        elif action == "disk_attach":
            disk_xml = request.json.get("xml", "")
            if not disk_xml:
                result = {"error": "ディスクXMLが必要です"}
            else:
                try:
                    import subprocess, tempfile
                    if 'bus=\'scsi\'' in disk_xml or "bus=\"scsi\"" in disk_xml:
                        ctrl_xml = "<controller type='scsi' index='0' model='virtio-scsi'/>"
                        with tempfile.NamedTemporaryFile(mode='w', suffix='.xml', delete=False) as f:
                            f.write(ctrl_xml)
                            ctrl_tmp = f.name
                        subprocess.run(
                            ["sudo", "virsh", "attach-device", name, "--file", ctrl_tmp, "--persistent"],
                            capture_output=True, text=True, timeout=10
                        )
                        subprocess.run(["sudo", "rm", "-f", ctrl_tmp], capture_output=True, timeout=5)
                    with tempfile.NamedTemporaryFile(mode='w', suffix='.xml', delete=False) as f:
                        f.write(disk_xml)
                        tmp_path = f.name
                    if dom.isActive():
                        r = subprocess.run(
                            ["sudo", "virsh", "attach-device", name, "--file", tmp_path, "--live", "--persistent"],
                            capture_output=True, text=True, timeout=10
                        )
                    else:
                        r = subprocess.run(
                            ["sudo", "virsh", "attach-device", name, "--file", tmp_path, "--persistent"],
                            capture_output=True, text=True, timeout=10
                        )
                    subprocess.run(["sudo", "rm", "-f", tmp_path], capture_output=True, timeout=5)
                    if r.returncode != 0:
                        result = {"error": r.stderr.strip() or r.stdout.strip()}
                except (subprocess.TimeoutExpired, Exception) as e:
                    result = {"error": str(e)}
        elif action == "disk_create_and_attach":
            disk_path = request.json.get("disk_path", "")
            disk_size = request.json.get("disk_size", "")
            disk_format = request.json.get("disk_format", "qcow2")
            target_dev = request.json.get("target_dev", "vdb")
            target_bus = request.json.get("target_bus", "virtio")
            if not disk_path or not disk_size:
                result = {"error": "パスと容量を指定してください"}
            else:
                try:
                    import subprocess, tempfile
                    if not disk_path.startswith("/"):
                        pool_path = "/opt/vm"
                        try:
                            vol = conn.storagePoolLookupByName("default").storageVolLookupByName(disk_path)
                            pool_path = os.path.dirname(vol.path())
                        except Exception:
                            pass
                        disk_path = os.path.join(pool_path, disk_path)
                    size_str = disk_size if disk_size.endswith(('G', 'M', 'K')) else f"{disk_size}G"
                    r = subprocess.run(
                        ["qemu-img", "create", "-f", disk_format, disk_path, size_str],
                        capture_output=True, text=True, timeout=30
                    )
                    if r.returncode != 0:
                        result = {"error": f"ディスク作成失敗: {r.stderr.strip()}"}
                    else:
                        subprocess.run(["sudo", "chown", "libvirt-qemu:kvm", disk_path], capture_output=True, timeout=5)
                        subprocess.run(["sudo", "chmod", "0644", disk_path], capture_output=True, timeout=5)
                        disk_xml = f"<disk type='file' device='disk'><driver name='qemu' type='{disk_format}'/><source file='{disk_path}'/><target dev='{target_dev}' bus='{target_bus}'/></disk>"
                        with tempfile.NamedTemporaryFile(mode='w', suffix='.xml', delete=False) as f:
                            f.write(disk_xml)
                            tmp_path = f.name
                        if dom.isActive():
                            r2 = subprocess.run(
                                ["sudo", "virsh", "attach-device", name, "--file", tmp_path, "--live", "--persistent"],
                                capture_output=True, text=True, timeout=10
                            )
                        else:
                            r2 = subprocess.run(
                                ["sudo", "virsh", "attach-device", name, "--file", tmp_path, "--persistent"],
                                capture_output=True, text=True, timeout=10
                            )
                        subprocess.run(["sudo", "rm", "-f", tmp_path], capture_output=True, timeout=5)
                        if r2.returncode != 0:
                            result = {"error": r2.stderr.strip() or r2.stdout.strip()}
                except (subprocess.TimeoutExpired, Exception) as e:
                    result = {"error": str(e)}
        elif action == "disk_detach":
            target_dev = request.json.get("target_dev", "")
            if not target_dev:
                result = {"error": "ターゲットデバイス名が必要です"}
            else:
                try:
                    xml_str = dom.XMLDesc(0)
                    root = ET.fromstring(xml_str)
                    devices_el = root.find(".//devices")
                    removed = False
                    for disk in root.findall(".//disk"):
                        target = disk.find("target")
                        if target is not None and target.get("dev") == target_dev:
                            devices_el.remove(disk)
                            removed = True
                            break
                    if not removed:
                        result = {"error": f"デバイス '{target_dev}' が見つかりません"}
                    else:
                        new_xml = ET.tostring(root, encoding="unicode")
                        conn.defineXML(new_xml)
                        result = {"success": True}
                except libvirt.libvirtError as e:
                    result = {"error": str(e)}
        elif action == "hostdev_detach":
            bus = request.json.get("bus", "")
            slot = request.json.get("slot", "")
            func = request.json.get("function", "")
            if not bus or not slot or not func:
                result = {"error": "バス、スロット、ファンクションが必要です"}
            else:
                try:
                    xml_str = dom.XMLDesc(0)
                    root = ET.fromstring(xml_str)
                    devices_el = root.find(".//devices")
                    removed = False
                    for hd in root.findall(".//hostdev"):
                        if hd.get("type") != "pci":
                            continue
                        src = hd.find("source")
                        if src is None:
                            continue
                        addr = src.find("address")
                        if addr is None:
                            continue
                        if (addr.get("bus", "") == bus and
                            addr.get("slot", "") == slot and
                            addr.get("function", "") == func):
                            devices_el.remove(hd)
                            removed = True
                            break
                    if not removed:
                        result = {"error": "PCIデバイスが見つかりません"}
                    else:
                        new_xml = ET.tostring(root, encoding="unicode")
                        conn.defineXML(new_xml)
                        result = {"success": True}
                except libvirt.libvirtError as e:
                    result = {"error": str(e)}
        elif action == "hostdev_attach":
            bus = request.json.get("bus", "")
            slot = request.json.get("slot", "")
            func = request.json.get("function", "")
            if not bus or not slot or not func:
                result = {"error": "バス、スロット、ファンクションが必要です"}
            else:
                try:
                    hostdev_xml = f"""<hostdev mode='subsystem' type='pci' managed='yes'>
  <source>
    <address domain='0x0000' bus='{bus}' slot='{slot}' function='{func}'/>
  </source>
</hostdev>"""
                    if dom.isActive():
                        conn.attachDevice(name, hostdev_xml)
                    else:
                        xml_str = dom.XMLDesc(0)
                        root = ET.fromstring(xml_str)
                        devices_el = root.find(".//devices")
                        hd_el = ET.fromstring(hostdev_xml)
                        devices_el.append(hd_el)
                        new_xml = ET.tostring(root, encoding="unicode")
                        conn.defineXML(new_xml)
                    result = {"success": True}
                except libvirt.libvirtError as e:
                    result = {"error": str(e)}
        elif action == "disk_update_source":
            target_dev = request.json.get("target_dev", "")
            new_source = request.json.get("new_source", "")
            if not target_dev:
                result = {"error": "ターゲットデバイス名が必要です"}
            elif dom.isActive():
                try:
                    import subprocess
                    if new_source:
                        r = subprocess.run(
                            ["sudo", "virsh", "change-media", name, target_dev, "--source", new_source],
                            capture_output=True, text=True, timeout=10
                        )
                    else:
                        r = subprocess.run(
                            ["sudo", "virsh", "change-media", name, target_dev, "--eject"],
                            capture_output=True, text=True, timeout=10
                        )
                    if r.returncode != 0:
                        result = {"error": r.stderr.strip() or r.stdout.strip()}
                    else:
                        result = {"success": True}
                except (subprocess.TimeoutExpired, Exception) as e:
                    result = {"error": str(e)}
            else:
                try:
                    xml_str = dom.XMLDesc(0)
                    root = ET.fromstring(xml_str)
                    updated = False
                    for disk in root.findall(".//disk"):
                        target = disk.find("target")
                        if target is not None and target.get("dev") == target_dev:
                            source = disk.find("source")
                            if new_source:
                                if source is not None:
                                    source.set("file", new_source)
                                else:
                                    source = ET.SubElement(disk, "source")
                                    source.set("file", new_source)
                            else:
                                if source is not None:
                                    disk.remove(source)
                            updated = True
                            break
                    if not updated:
                        result = {"error": f"デバイス '{target_dev}' が見つかりません"}
                    else:
                        new_xml = ET.tostring(root, encoding="unicode")
                        conn.defineXML(new_xml)
                        result = {"success": True}
                except libvirt.libvirtError as e:
                    result = {"error": str(e)}
        elif action == "disk_resize":
            target_dev = request.json.get("target_dev", "")
            new_size = request.json.get("new_size", "")
            if not target_dev or not new_size:
                result = {"error": "ターゲットデバイス名と新しいサイズが必要です"}
            elif dom.isActive():
                result = {"error": "VMを停止してからディスクを拡大してください"}
            else:
                try:
                    xml_str = dom.XMLDesc(0)
                    root = ET.fromstring(xml_str)
                    disk_path = ""
                    for disk in root.findall(".//disk"):
                        target = disk.find("target")
                        if target is not None and target.get("dev") == target_dev:
                            source = disk.find("source")
                            if source is not None:
                                disk_path = source.get("file", "")
                            break
                    if not disk_path:
                        result = {"error": f"デバイス '{target_dev}' のパスが見つかりません"}
                    else:
                        import subprocess
                        r = subprocess.run(
                            ["qemu-img", "info", "--output=json", disk_path],
                            capture_output=True, text=True, timeout=10
                        )
                        if r.returncode != 0:
                            result = {"error": f"ディスク情報の取得に失敗: {r.stderr.strip()}"}
                        else:
                            import json
                            info = json.loads(r.stdout)
                            old_size = info.get("virtual-size", 0)
                            r2 = subprocess.run(
                                ["qemu-img", "resize", disk_path, new_size],
                                capture_output=True, text=True, timeout=30
                            )
                            if r2.returncode != 0:
                                result = {"error": f"リサイズ失敗: {r2.stderr.strip()}"}
                            else:
                                r3 = subprocess.run(
                                    ["qemu-img", "info", "--output=json", disk_path],
                                    capture_output=True, text=True, timeout=10
                                )
                                new_info = json.loads(r3.stdout) if r3.returncode == 0 else {}
                                result = {
                                    "success": True,
                                    "old_size": old_size,
                                    "new_size": new_info.get("virtual-size", 0)
                                }
                except Exception as e:
                    result = {"error": str(e)}
        else:
            conn.close()
            return jsonify({"error": f"不明なアクション: {action}"}), 400
        result = {"success": True}
    except libvirt.libvirtError as e:
        result = {"error": str(e)}
    conn.close()
    return jsonify(result)


@app.route("/vm/create", methods=["GET", "POST"])
def vm_create():
    conn = get_conn()
    storage_pools = []
    for pname in conn.listStoragePools():
        pool = conn.storagePoolLookupByName(pname)
        pool.refresh(0)
        storage_pools.append({
            "name": pname,
            "active": pool.isActive(),
            "type": pool.info()[0],
        })

    networks = []
    for nname in conn.listNetworks():
        net = conn.networkLookupByName(nname)
        networks.append({"name": nname, "active": net.isActive()})

    hostdevs = []
    try:
        for nd in conn.listAllNodeDevices(0):
            try:
                nd_xml = nd.XMLDesc(0)
                nd_root = ET.fromstring(nd_xml)
                driver_el = nd_root.find("driver")
                if driver_el is not None and driver_el.get("name") == "vfio-pci":
                    cap = nd_root.find("capability")
                    vendor_el = cap.find("vendor") if cap is not None else None
                    product_el = cap.find("product") if cap is not None else None
                    hostdevs.append({
                        "name": nd.name(),
                        "vendor_id": vendor_el.get("id", "") if vendor_el is not None else "",
                        "product_id": product_el.get("id", "") if product_el is not None else "",
                        "description": cap.get("id", "") if cap is not None else nd.name(),
                    })
            except Exception:
                continue
    except Exception:
        pass

    conn.close()

    if request.method == "POST":
        config = request.json
        try:
            conn = get_conn()

            disk_size_gb = config.get("disk_size_gb", "")
            disk_pool = config.get("disk_pool", "default")
            vm_name = config.get("name", "").strip()
            disk_path = ""
            if disk_size_gb not in ("0", "existing", "") and vm_name:
                try:
                    disk_path = _create_volume(conn, vm_name, disk_pool, int(disk_size_gb))
                except (ValueError, TypeError):
                    pass
            config["_disk_path"] = disk_path

            disks_config = config.get("disks", [])
            for dc in disks_config:
                if dc.get("type") == "file_create":
                    fpath = dc.get("disk_path", "")
                    fsize = dc.get("disk_size", "")
                    ffmt = dc.get("driver_type", "qcow2")
                    if fpath and fsize:
                        if not fpath.startswith("/"):
                            pool_dir = "/opt/vm"
                            try:
                                _conn = get_conn()
                                _vol = _conn.storagePoolLookupByName("default").storageVolLookupByName(fpath)
                                pool_dir = os.path.dirname(_vol.path())
                                _conn.close()
                            except Exception:
                                pass
                            fpath = os.path.join(pool_dir, fpath)
                        size_str = fsize if fsize.endswith(('G', 'M', 'K')) else f"{fsize}G"
                        import subprocess as _sp
                        _sp.run(["qemu-img", "create", "-f", ffmt, fpath, size_str],
                            capture_output=True, timeout=30)
                        _sp.run(["sudo", "chown", "libvirt-qemu:kvm", fpath], capture_output=True, timeout=5)
                        _sp.run(["sudo", "chmod", "0644", fpath], capture_output=True, timeout=5)
                    dc["type"] = "file"
                    dc["source_file"] = fpath

            xml, errors = _build_vm_xml(config)
            if errors:
                conn.close()
                return jsonify({"error": errors}), 400

            conn.defineXML(xml)

            autostart = config.get("autostart", False)
            if autostart:
                dom = conn.lookupByName(vm_name)
                dom.setAutostart(1)

            conn.close()
            return jsonify({"success": True, "name": vm_name})
        except libvirt.libvirtError as e:
            return jsonify({"error": str(e)}), 400

    usb_devices = _get_usb_devices()

    return render_template(
        "vm_create.html",
        storage_pools=storage_pools,
        networks=networks,
        hostdevs=hostdevs,
        usb_devices=usb_devices,
    )


@app.route("/vm/create-xml", methods=["POST"])
def vm_create_xml():
    data = request.json
    xml = data.get("xml", "").strip()
    if not xml:
        return jsonify({"error": "XMLが空です"}), 400

    try:
        root = ET.fromstring(xml)
        name_el = root.find("name")
        if name_el is None or not name_el.text:
            return jsonify({"error": "XMLに<name>タグが見つかりません"}), 400
        vm_name = name_el.text.strip()
    except ET.ParseError as e:
        return jsonify({"error": f"XMLのパースエラー: {e}"}), 400

    try:
        conn = get_conn()
        conn.defineXML(xml)
        conn.close()
        return jsonify({"success": True, "name": vm_name})
    except libvirt.libvirtError as e:
        return jsonify({"error": str(e)}), 400


def _create_volume(conn, vm_name, pool_name, size_gb):
    try:
        pool = conn.storagePoolLookupByName(pool_name)
    except libvirt.libvirtError:
        return

    vol_name = f"{vm_name}.qcow2"

    vol_xml = f"""
    <volume>
      <name>{vol_name}</name>
      <capacity unit='G'>{size_gb}</capacity>
      <target>
        <format type='qcow2'/>
      </target>
    </volume>"""

    try:
        vol = pool.createXML(vol_xml, 0)
    except libvirt.libvirtError:
        try:
            vol = pool.storageVolLookupByName(vol_name)
        except libvirt.libvirtError:
            return ""

    vol_path = ""
    try:
        vol_path = vol.path()
        import subprocess
        subprocess.run(
            ["sudo", "chown", "libvirt-qemu:kvm", vol_path],
            capture_output=True, timeout=5, check=True
        )
        subprocess.run(
            ["sudo", "chmod", "0644", vol_path],
            capture_output=True, timeout=5, check=True
        )
    except Exception:
        pass

    return vol_path


def _build_vm_xml(config):
    name = config.get("name", "").strip()
    if not name:
        return None, "VM名を入力してください"

    domain_type = config.get("domain_type", "kvm")
    vcpus = int(config.get("vcpus", 2))
    memory_mb = int(config.get("memory_mb", 4096))
    memory_kb = memory_mb * 1024

    arch = config.get("arch", "x86_64")
    machine = config.get("machine", "pc-q35-10.2")

    disk_size_gb = config.get("disk_size_gb", "")
    disk_pool = config.get("disk_pool", "default")
    disk_bus = config.get("disk_bus", "virtio")

    net_type = config.get("net_type", "network")
    net_source = config.get("net_source", "default")
    net_model = config.get("net_model", "virtio")

    vnc_port = config.get("vnc_port", "") or "-1"
    try:
        int(vnc_port)
    except (ValueError, TypeError):
        vnc_port = "-1"
    vnc_listen = config.get("vnc_listen", "") or "0.0.0.0"
    vnc_passwd = config.get("vnc_passwd", "")

    spice_enabled = config.get("spice_enabled", False)
    spice_port = config.get("spice_port", "") or "-1"
    try:
        int(spice_port)
    except (ValueError, TypeError):
        spice_port = "-1"
    spice_tls_port = config.get("spice_tls_port", "") or ""
    spice_listen = config.get("spice_listen", "") or "0.0.0.0"

    video_model = config.get("video_model", "")
    if not video_model:
        video_model = "qxl" if spice_enabled else "virtio"
    tpm_enabled = config.get("tpm_enabled", False)
    sound_enabled = config.get("sound_enabled", False)
    channel_spice = config.get("channel_spice", False)
    usb_redirector_1 = config.get("usb_redirector_1", False)
    usb_redirector_2 = config.get("usb_redirector_2", False)
    boot_order = config.get("boot_order", [])

    disks_config = config.get("disks", [])
    hostdevs = config.get("hostdevs", [])
    existing_usbs = config.get("existing_usbs", [])

    lines = []
    lines.append(f'<domain type="{domain_type}">')
    lines.append(f"  <name>{name}</name>")
    lines.append(f"  <memory unit='KiB'>{memory_kb}</memory>")
    lines.append(f"  <currentMemory unit='KiB'>{memory_kb}</currentMemory>")
    lines.append(f"  <vcpu placement='static'>{vcpus}</vcpu>")
    lines.append("  <cpu mode='host-passthrough' check='none'>")
    lines.append(f"    <topology sockets='1' dies='1' cores='{vcpus}' threads='1'/>")
    lines.append("  </cpu>")
    uefi = config.get("uefi", False)
    secure_boot = config.get("secure_boot", False)
    boot_order = config.get("boot_order", [])
    if uefi:
        if secure_boot:
            lines.append("  <os firmware='efi'>")
            lines.append(f"    <type arch='{arch}' machine='{machine}'>hvm</type>")
            lines.append("    <firmware>")
            lines.append("      <feature enabled='yes' name='enrolled-keys'/>")
            lines.append("      <feature enabled='yes' name='secure-boot'/>")
            lines.append("    </firmware>")
            lines.append("    <loader readonly='yes' secure='yes' type='pflash' format='raw'>/usr/share/OVMF/OVMF_CODE_4M.ms.fd</loader>")
            lines.append(f"    <nvram template='/usr/share/OVMF/OVMF_VARS_4M.ms.fd' templateFormat='raw' format='raw'>/var/lib/libvirt/qemu/nvram/{name}_VARS.fd</nvram>")
        else:
            lines.append("  <os firmware='efi'>")
            lines.append(f"    <type arch='{arch}' machine='{machine}'>hvm</type>")
            lines.append("    <firmware>")
            lines.append("      <feature enabled='no' name='enrolled-keys'/>")
            lines.append("      <feature enabled='no' name='secure-boot'/>")
            lines.append("    </firmware>")
            lines.append("    <loader readonly='yes' secure='no' type='pflash' stateless='yes' format='raw'>/usr/share/ovmf/OVMF.amdsev.fd</loader>")
        if boot_order:
            for dev in boot_order:
                lines.append(f"    <boot dev='{dev}'/>")
        else:
            lines.append("    <boot dev='hd'/>")
        lines.append("    <bootmenu enable='yes'/>")
    else:
        lines.append("  <os>")
        lines.append(f"    <type arch='{arch}' machine='{machine}'>hvm</type>")
        if boot_order:
            for dev in boot_order:
                lines.append(f"    <boot dev='{dev}'/>")
        else:
            lines.append("    <boot dev='hd'/>")
    lines.append("  </os>")
    lines.append("  <features>")
    lines.append("    <acpi/>")
    lines.append("    <apic/>")
    lines.append("  </features>")
    lines.append("  <clock offset='utc'/>")
    lines.append("  <devices>")

    try:
        disk_size_int = int(disk_size_gb) if disk_size_gb else 0
    except (ValueError, TypeError):
        disk_size_int = 0

    if disk_size_int > 0:
        disk_path = config.get("_disk_path", "")
        if disk_path:
            lines.append("    <disk type='file' device='disk'>")
            lines.append("      <driver name='qemu' type='qcow2'/>")
            lines.append(f"      <source file='{disk_path}'/>")
            lines.append(f"      <target dev='vda' bus='{disk_bus}'/>")
            lines.append("    </disk>")
        else:
            lines.append("    <disk type='volume' device='disk'>")
            lines.append("      <driver name='qemu' type='qcow2'/>")
            lines.append(f"      <source pool='{disk_pool}' volume='{name}.qcow2'/>")
            lines.append(f"      <target dev='vda' bus='{disk_bus}'/>")
            lines.append("    </disk>")
    elif disk_size_gb == "existing":
        existing_path = config.get("existing_disk_path", "").strip()
        if existing_path:
            lines.append("    <disk type='file' device='disk'>")
            lines.append("      <driver name='qemu' type='qcow2'/>")
            lines.append(f"      <source file='{existing_path}'/>")
            lines.append(f"      <target dev='vda' bus='{disk_bus}'/>")
            lines.append("    </disk>")

    dev_letters = "bcdefghijklmnop"
    dev_idx = 0

    iso_paths = config.get("iso_paths", [])
    iso_idx = 0
    for iso in iso_paths:
        if isinstance(iso, dict):
            iso_path = iso.get("path", "").strip()
            iso_target = iso.get("target", "").strip()
        else:
            iso_path = str(iso).strip()
            iso_target = ""
        if iso_path or iso_target:
            dev = iso_target if iso_target else f"sd{chr(ord('c') + iso_idx)}"
            lines.append("    <disk type='file' device='cdrom'>")
            lines.append("      <driver name='qemu' type='raw'/>")
            if iso_path:
                lines.append(f"      <source file='{iso_path}'/>")
            lines.append(f"      <target dev='{dev}' bus='sata'/>")
            lines.append("      <readonly/>")
            lines.append("    </disk>")
            iso_idx += 1

    for dc in disks_config:
        dtype = dc.get("type", "")
        if dtype == "block_lun":
            lines.append("    <disk type='block' device='lun'>")
            driver_type = dc.get("driver_type", "raw")
            lines.append(f"      <driver name='qemu' type='{driver_type}'/>")
            lines.append(f"      <source dev='{dc.get('source_dev', '')}'/>")
            target_dev = dc.get("target_dev", f"sd{dev_letters[dev_idx]}")
            target_bus = dc.get("target_bus", "scsi")
            lines.append(f"      <target dev='{target_dev}' bus='{target_bus}'/>")
            lines.append("    </disk>")
        elif dtype == "block":
            lines.append("    <disk type='block' device='disk'>")
            driver_type = dc.get("driver_type", "raw")
            lines.append(f"      <driver name='qemu' type='{driver_type}'/>")
            lines.append(f"      <source dev='{dc.get('source_dev', '')}'/>")
            target_dev = dc.get("target_dev", f"vd{dev_letters[dev_idx]}")
            target_bus = dc.get("target_bus", "virtio")
            lines.append(f"      <target dev='{target_dev}' bus='{target_bus}'/>")
            lines.append("    </disk>")
        elif dtype == "file":
            lines.append("    <disk type='file' device='disk'>")
            driver_type = dc.get("driver_type", "qcow2")
            lines.append(f"      <driver name='qemu' type='{driver_type}'/>")
            lines.append(f"      <source file='{dc.get('source_file', '')}'/>")
            target_dev = dc.get("target_dev", f"vd{dev_letters[dev_idx]}")
            target_bus = dc.get("target_bus", "virtio")
            lines.append(f"      <target dev='{target_dev}' bus='{target_bus}'/>")
            lines.append("    </disk>")
        dev_idx += 1

    has_scsi = any(dc.get("target_bus") == "scsi" for dc in disks_config)
    if has_scsi:
        lines.append("    <controller type='scsi' index='0' model='virtio-scsi'/>")

    lines.append(f"    <graphics type='vnc' port='{vnc_port}' autoport='yes' listen='{vnc_listen}'>")
    lines.append(f"      <listen type='address' address='{vnc_listen}'/>")
    lines.append("    </graphics>")

    if spice_enabled:
        spice_attrs = f"    <graphics type='spice' port='{spice_port}' autoport='yes' listen='{spice_listen}'"
        if spice_tls_port:
            spice_attrs += f" tlsPort='{spice_tls_port}'"
        spice_attrs += ">"
        lines.append(spice_attrs)
        lines.append(f"      <listen type='address' address='{spice_listen}'/>")
        lines.append("      <image compression='off'/>")
        lines.append("      <playback compression='on'/>")
        lines.append("      <streaming mode='filter'/>")
        lines.append("      <clipboard copypaste='yes'/>")
        lines.append("      <filetransfer enable='yes'/>")
        lines.append("    </graphics>")

    lines.append(f"    <interface type='{net_type}'>")
    if net_type == "network":
        lines.append(f"      <source network='{net_source}'/>")
    elif net_type == "bridge":
        lines.append(f"      <source bridge='{net_source}'/>")
    elif net_type == "direct":
        lines.append(f"      <source dev='{net_source}'/>")
    lines.append(f"      <model type='{net_model}'/>")
    lines.append("    </interface>")

    for hd in hostdevs:
        hd_domain = hd.get("domain", "0x0000")
        hd_bus = hd.get("bus", "0x00")
        hd_slot = hd.get("slot", "0x00")
        hd_function = hd.get("function", "0x0")
        lines.append("    <hostdev mode='subsystem' type='pci' managed='yes'>")
        lines.append("      <source>")
        lines.append(f"        <address domain='{hd_domain}' bus='{hd_bus}' slot='{hd_slot}' function='{hd_function}'/>")
        lines.append("      </source>")
        lines.append("    </hostdev>")

    for uhd in existing_usbs:
        lines.append("    <hostdev mode='subsystem' type='usb' managed='yes'>")
        lines.append("      <source>")
        lines.append(f"        <vendor id='{uhd['vendor_id']}'/>")
        lines.append(f"        <product id='{uhd['product_id']}'/>")
        lines.append("      </source>")
        lines.append("    </hostdev>")

    usb_hostdevs = config.get("usb_hostdevs", [])
    for uhd in usb_hostdevs:
        lines.append("    <hostdev mode='subsystem' type='usb' managed='yes'>")
        lines.append("      <source>")
        lines.append(f"        <vendor id='0x{uhd['vendor_id']}'/>")
        lines.append(f"        <product id='0x{uhd['product_id']}'/>")
        lines.append("      </source>")
        lines.append("    </hostdev>")

    lines.append("    <video>")
    if video_model == "qxl":
        lines.append("      <model type='qxl' ram='65536' vram='65536' vgamem='16384' heads='1'/>")
    else:
        lines.append("      <model type='virtio' heads='1'/>")
    lines.append("    </video>")

    if tpm_enabled:
        lines.append("    <tpm model='tpm-crb'>")
        lines.append("      <backend type='emulator'/>")
        lines.append("    </tpm>")

    if sound_enabled:
        lines.append("    <sound model='ich9'/>")

    if channel_spice:
        lines.append("    <channel type='spicevmc'>")
        lines.append("      <target type='virtio' name='com.redhat.spice.0'/>")
        lines.append("    </channel>")

    usb_tablet = config.get("usb_tablet", False)
    if usb_tablet:
        lines.append("    <input type='tablet' bus='usb'/>")

    if usb_redirector_1:
        lines.append("    <redirdev bus='usb' type='spicevmc'/>")
    if usb_redirector_2:
        lines.append("    <redirdev bus='usb' type='spicevmc'/>")

    has_scsi = any(dc.get("target_bus") == "scsi" or dc.get("type") == "block_lun" for dc in disks_config)
    if has_scsi:
        lines.append("    <controller type='scsi' index='0' model='virtio-scsi'/>")

    lines.append("    <memballoon model='virtio'/>")
    lines.append("  </devices>")
    lines.append("  <seclabel type='dynamic' model='apparmor' relabel='yes'/>")
    lines.append("</domain>")

    return "\n".join(lines), None


@app.route("/api/vm/<name>/xml", methods=["GET", "PUT"])
def vm_xml(name):
    conn = get_conn()
    try:
        dom = conn.lookupByName(name)
    except libvirt.libvirtError:
        conn.close()
        return jsonify({"error": f"VM '{name}' が見つかりません"}), 404

    if request.method == "GET":
        xml_str = dom.XMLDesc(0)
        conn.close()
        return jsonify({"xml": xml_str})
    else:
        new_xml = request.json.get("xml", "")
        try:
            conn.defineXML(new_xml)
            conn.close()
            return jsonify({"success": True})
        except libvirt.libvirtError as e:
            conn.close()
            return jsonify({"error": str(e)}), 400


@app.route("/api/vm/<name>/bootorder", methods=["GET", "PUT"])
def vm_bootorder(name):
    conn = get_conn()
    try:
        dom = conn.lookupByName(name)
    except libvirt.libvirtError:
        conn.close()
        return jsonify({"error": f"VM '{name}' が見つかりません"}), 404

    if dom.isActive():
        conn.close()
        return jsonify({"error": "VMを停止してからブート順序を変更してください"}), 400

    if request.method == "GET":
        xml_str = dom.XMLDesc(0)
        root = ET.fromstring(xml_str)
        boot_order = []
        idx = 1
        for os_boot in root.findall(".//os/boot"):
            dev = os_boot.get("dev", "")
            if dev:
                boot_order.append({"dev": dev, "order": idx})
                idx += 1
        conn.close()
        return jsonify({"boot_order": boot_order})
    else:
        boot_devs = request.json.get("boot_order", [])
        xml_str = dom.XMLDesc(0)
        root = ET.fromstring(xml_str)

        for os_boot in root.findall(".//os/boot"):
            root.find(".//os").remove(os_boot)

        os_el = root.find(".//os")
        for bd in boot_devs:
            dev = bd.get("dev", "")
            if dev:
                boot_el = ET.SubElement(os_el, "boot")
                boot_el.set("dev", dev)

        new_xml = ET.tostring(root, encoding="unicode")
        try:
            conn.defineXML(new_xml)
            conn.close()
            return jsonify({"success": True})
        except libvirt.libvirtError as e:
            conn.close()
            return jsonify({"error": str(e)}), 400


@app.route("/api/storage")
def api_storage():
    conn = get_conn()
    pools = []
    for pname in conn.listStoragePools():
        pool = conn.storagePoolLookupByName(pname)
        pool.refresh(0)
        info = pool.info()
        volumes = []
        for vol_name in pool.listVolumes():
            vol = pool.storageVolLookupByName(vol_name)
            vol_info = vol.info()
            volumes.append({
                "name": vol_name,
                "capacity_mb": vol_info[1] // (1024 * 1024),
                "allocation_mb": vol_info[2] // (1024 * 1024),
            })
        pools.append({
            "name": pname,
            "active": pool.isActive(),
            "type": info[0],
            "capacity_mb": info[1] // (1024 * 1024),
            "allocation_mb": info[2] // (1024 * 1024),
            "volumes": volumes,
        })
    conn.close()
    return jsonify(pools)


@app.route("/api/block-devices")
def api_block_devices():
    import subprocess
    devices = []
    try:
        result = subprocess.run(
            ["lsblk", "-J", "-o", "NAME,SIZE,TYPE,MOUNTPOINT,MODEL"],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            import json
            data = json.loads(result.stdout)
            for dev in data.get("blockdevices", []):
                name = dev.get("name", "")
                dev_type = dev.get("type", "")
                size = dev.get("size", "")
                model = (dev.get("model") or "").strip()
                mountpoint = dev.get("mountpoint") or ""
                if dev_type in ("disk", "part", "lvm"):
                    label = f"/dev/{name}"
                    if model:
                        label += f" ({model})"
                    label += f" - {size}"
                    if mountpoint:
                        label += f" [{mountpoint}]"
                    devices.append({
                        "path": f"/dev/{name}",
                        "name": name,
                        "size": size,
                        "type": dev_type,
                        "model": model,
                        "mountpoint": mountpoint,
                        "label": label,
                    })
                for child in dev.get("children", []):
                    cname = child.get("name", "")
                    ctype = child.get("type", "")
                    csize = child.get("size", "")
                    cmodel = (child.get("model") or "").strip()
                    cmountpoint = child.get("mountpoint") or ""
                    if ctype in ("part", "lvm"):
                        clabel = f"/dev/{cname}"
                        if cmodel:
                            clabel += f" ({cmodel})"
                        clabel += f" - {csize}"
                        if cmountpoint:
                            clabel += f" [{cmountpoint}]"
                        devices.append({
                            "path": f"/dev/{cname}",
                            "name": cname,
                            "size": csize,
                            "type": ctype,
                            "model": cmodel,
                            "mountpoint": cmountpoint,
                            "label": clabel,
                        })
    except Exception:
        pass
    return jsonify(devices)


@app.route("/api/storage-pool-volumes")
def api_storage_pool_volumes():
    conn = get_conn()
    volumes = []
    for pname in conn.listStoragePools():
        try:
            pool = conn.storagePoolLookupByName(pname)
            pool.refresh(0)
            for vol_name in pool.listVolumes():
                vol = pool.storageVolLookupByName(vol_name)
                vol_info = vol.info()
                vol_path = vol.path()
                size_mb = vol_info[1] // (1024 * 1024)
                volumes.append({
                    "path": vol_path,
                    "name": vol_name,
                    "pool": pname,
                    "size_mb": size_mb,
                    "label": f"[{pname}] {vol_name} ({size_mb} MB)",
                })
        except Exception:
            continue
    conn.close()
    return jsonify(volumes)


@app.route("/api/iso-files")
def api_iso_files():
    conn = get_conn()
    isos = []
    iso_exts = ('.iso', '.img', '.raw', '.qcow2', '.vmdk', '.vhdx', '.vdi')
    for pname in conn.listStoragePools():
        try:
            pool = conn.storagePoolLookupByName(pname)
            pool.refresh(0)
            for vol_name in pool.listVolumes():
                if any(vol_name.lower().endswith(ext) for ext in iso_exts):
                    vol = pool.storageVolLookupByName(vol_name)
                    vol_info = vol.info()
                    isos.append({
                        "name": vol_name,
                        "path": vol.path(),
                        "pool": pname,
                        "size_mb": vol_info[1] // (1024 * 1024),
                        "label": f"[{pname}] {vol_name} ({vol_info[1] // (1024 * 1024)} MB)",
                    })
        except Exception:
            continue
    conn.close()
    return jsonify(isos)


@app.route("/api/networks")
def api_networks():
    conn = get_conn()
    networks = []
    for nname in conn.listNetworks():
        net = conn.networkLookupByName(nname)
        networks.append({
            "name": nname,
            "active": net.isActive(),
            "autostart": net.autostart(),
            "bridge": net.bridgeName() if net.bridgeName() else "",
        })
    conn.close()
    return jsonify(networks)


_websockify_procs = {}

WEBSOCKIFY_PORT = 6080
WEBSOCKIFY_TARGETS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "websockify-targets.cfg")

import subprocess as _sp


def _ws_url(vm_name=None):
    url = f"wss://{request.host}/websockify"
    if vm_name:
        url += f"?token={vm_name}"
    return url


def _vm_vnc_port(dom):
    try:
        root = ET.fromstring(dom.XMLDesc(0))
    except Exception:
        return None
    for graphics in root.findall(".//graphics"):
        if graphics.get("type") == "vnc":
            port = graphics.get("port", "")
            if port and port.isdigit():
                return port
            return None
    return None


def _write_targets(conn):
    lines = []
    for dom in conn.listAllDomains(libvirt.VIR_CONNECT_LIST_DOMAINS_ACTIVE):
        port = _vm_vnc_port(dom)
        if port:
            lines.append(f"{dom.name()}: 127.0.0.1:{port}")
    tmp = WEBSOCKIFY_TARGETS + ".tmp"
    with open(tmp, "w") as f:
        f.write("\n".join(lines) + ("\n" if lines else ""))
    os.replace(tmp, WEBSOCKIFY_TARGETS)


def _ensure_websockify():
    proc = _websockify_procs.get("_main")
    if proc and proc.poll() is None:
        return True
    try:
        proc = _sp.Popen(
            ["websockify", "--web", "/usr/share/novnc/",
             "--token-plugin", "TokenFile",
             "--token-source", WEBSOCKIFY_TARGETS,
             f"127.0.0.1:{WEBSOCKIFY_PORT}"],
            stdout=_sp.DEVNULL, stderr=_sp.DEVNULL)
    except FileNotFoundError:
        return False
    _websockify_procs["_main"] = proc
    return True


def _ws_warmup(vm_name, timeout=10):
    """Block until a complete WebSocket upgrade through websockify to the
    VM's VNC port relays the RFB greeting. This boots websockify's
    forkserver and absorbs the first-connection race so the browser's
    first connection is reliable."""
    import base64
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            sock = socket.create_connection(("127.0.0.1", WEBSOCKIFY_PORT), timeout=1)
        except OSError:
            time.sleep(0.2)
            continue
        try:
            sock.settimeout(2)
            key = base64.b64encode(os.urandom(16)).decode()
            req = ("GET /?token={} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n"
                   "Upgrade: websocket\r\nConnection: Upgrade\r\n"
                   "Sec-WebSocket-Key: {}\r\nSec-WebSocket-Version: 13\r\n\r\n").format(
                       vm_name, WEBSOCKIFY_PORT, key)
            sock.sendall(req.encode())
            resp = b""
            while b"\r\n\r\n" not in resp:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                resp += chunk
            if b"101" in resp:
                rest = resp.partition(b"\r\n\r\n")[2]
                while len(rest) < 12:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    rest += chunk
                if b"RFB" in rest:
                    return True
        except OSError:
            pass
        finally:
            try:
                sock.close()
            except Exception:
                pass
        time.sleep(0.2)
    return False


@app.route("/api/vm/<name>/snapshots")
def api_snapshots(name):
    conn = get_conn()
    try:
        dom = conn.lookupByName(name)
    except libvirt.libvirtError:
        conn.close()
        return jsonify({"error": f"VM '{name}' が見つかりません"}), 404

    snapshots = []
    try:
        for snap in dom.listAllSnapshots(0):
            xml_str = snap.getXMLDesc(0)
            root = ET.fromstring(xml_str)
            creation = root.findtext("creationTime", "0")
            state = root.findtext("state", "unknown")
            sname = root.findtext("name", "")
            desc = root.findtext("description", "")
            snapshots.append({
                "name": sname,
                "state": state,
                "creation": int(creation) if creation else 0,
                "description": desc,
            })
    except libvirt.libvirtError:
        pass
    conn.close()
    snapshots.sort(key=lambda s: s["creation"], reverse=True)
    return jsonify(snapshots)


@app.route("/api/vm/<name>/snapshot-create", methods=["POST"])
def api_snapshot_create(name):
    conn = get_conn()
    try:
        dom = conn.lookupByName(name)
    except libvirt.libvirtError:
        conn.close()
        return jsonify({"error": f"VM '{name}' が見つかりません"}), 404

    config = request.json or {}
    snap_name = config.get("name", "").strip()
    snap_desc = config.get("description", "").strip()

    if not snap_name:
        import datetime
        snap_name = datetime.datetime.now().strftime("snap-%Y%m%d-%H%M%S")

    snap_xml = f"""<domainsnapshot>
    <name>{snap_name}</name>
    <description>{snap_desc}</description>
</domainsnapshot>"""

    try:
        flags = libvirt.VIR_DOMAIN_SNAPSHOT_CREATE_ATOMIC
        dom.snapshotCreateXML(snap_xml, flags)
        conn.close()
        return jsonify({"success": True})
    except libvirt.libvirtError as e:
        conn.close()
        return jsonify({"error": str(e)}), 400


@app.route("/api/vm/<name>/snapshot-delete", methods=["POST"])
def api_snapshot_delete(name):
    conn = get_conn()
    try:
        dom = conn.lookupByName(name)
    except libvirt.libvirtError:
        conn.close()
        return jsonify({"error": f"VM '{name}' が見つかりません"}), 404

    snap_name = (request.json or {}).get("name", "")
    if not snap_name:
        conn.close()
        return jsonify({"error": "スナップショット名が必要です"}), 400

    try:
        snap = dom.snapshotLookupByName(snap_name, 0)
        snap.delete(0)
        conn.close()
        return jsonify({"success": True})
    except libvirt.libvirtError as e:
        conn.close()
        return jsonify({"error": str(e)}), 400


@app.route("/api/vm/<name>/snapshot-revert", methods=["POST"])
def api_snapshot_revert(name):
    conn = get_conn()
    try:
        dom = conn.lookupByName(name)
    except libvirt.libvirtError:
        conn.close()
        return jsonify({"error": f"VM '{name}' が見つかりません"}), 404

    if dom.isActive():
        conn.close()
        return jsonify({"error": "VMを停止してから元に戻してください"}), 400

    snap_name = (request.json or {}).get("name", "")
    if not snap_name:
        conn.close()
        return jsonify({"error": "スナップショット名が必要です"}), 400

    try:
        snap = dom.snapshotLookupByName(snap_name, 0)
        flags = libvirt.VIR_DOMAIN_SNAPSHOT_REVERT_RUNNING
        dom.revertToSnapshot(snap, flags)
        conn.close()
        return jsonify({"success": True})
    except libvirt.libvirtError as e:
        conn.close()
        return jsonify({"error": str(e)}), 400


@app.route("/api/vm/<name>/vnc-info")
def api_vnc_info(name):
    conn = get_conn()
    try:
        dom = conn.lookupByName(name)
    except libvirt.libvirtError:
        conn.close()
        return jsonify({"error": f"VM '{name}' が見つかりません"}), 404

    xml_str = dom.XMLDesc(0)
    root = ET.fromstring(xml_str)
    vnc_port = None
    vnc_listen = "127.0.0.1"
    for graphics in root.findall(".//graphics"):
        if graphics.get("type") == "vnc":
            vnc_port = graphics.get("port", "")
            vnc_listen = graphics.get("listen", "127.0.0.1")
            listen_el = graphics.find("listen")
            if listen_el is not None:
                vnc_listen = listen_el.get("address", vnc_listen)
            break
    is_active = dom.isActive()
    conn.close()
    if not vnc_port:
        return jsonify({"error": "VNCが有効ではありません"}), 400
    return jsonify({"port": vnc_port, "listen": vnc_listen, "active": is_active})


@app.route("/api/vm/<name>/status")
def api_vm_status(name):
    conn = get_conn()
    try:
        dom = conn.lookupByName(name)
    except libvirt.libvirtError:
        conn.close()
        return jsonify({"error": f"VM '{name}' が見つかりません"}), 404
    is_active = dom.isActive()
    conn.close()
    return jsonify({"active": is_active})


@app.route("/api/vm/<name>/console-proxy", methods=["POST", "DELETE"])
def console_proxy(name):
    if request.method == "DELETE":
        return jsonify({"success": True})

    conn = get_conn()
    try:
        dom = conn.lookupByName(name)
    except libvirt.libvirtError:
        conn.close()
        return jsonify({"error": f"VM '{name}' が見つかりません"}), 404

    vnc_port = _vm_vnc_port(dom)
    if not vnc_port:
        conn.close()
        return jsonify({"error": "VNCポートが未割り当てです（VMが起動していない可能性があります）"}), 400

    if not _ensure_websockify():
        conn.close()
        return jsonify({"error": "websockifyがインストールされていません。 sudo apt install novnc python3-websockify"}), 500

    _write_targets(conn)
    conn.close()

    if not _ws_warmup(name):
        return jsonify({"error": "コンソールの準備に失敗しました。もう一度お試しください"}), 503

    return jsonify({"ws_port": WEBSOCKIFY_PORT, "ws_url": _ws_url(name)})


@app.route("/vm/<name>/console")
def vm_console(name):
    return render_template("vm_console.html", vm_name=name)


@app.route("/novnc/<path:filename>")
def novnc_static(filename):
    from flask import send_from_directory
    return send_from_directory("/usr/share/novnc", filename)


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8090, debug=False)
