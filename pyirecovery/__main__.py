# pyirecovery - A CLI wrapper of pymobiledevice3 that interacts with Recovery/DFU Apple devices
# Copyright (C) 2023 MiniExploit

import click
from pymobiledevice3 import irecv, irecv_devices
from pymobiledevice3.exceptions import PyMobileDevice3Exception, IRecvNoDeviceConnectedError
import usb.core, usb.util
import binascii
import readline
import os, sys
from enum import Enum

BUFFER_SIZE = 0x1000
HISTORY_FILE = os.path.expanduser('.pyirecovery_history')
SHELL_USAGE = """
Usage:
  /upload FILE\t\tSend file to device
  /deviceinfo\t\tPrint device information
  /help\t\tShow this help
  /exit\t\tExit interactive help
"""

class CommandType(Enum):
    UPLOAD = 1
    DEVINFO = 2
    EXIT = 3
    HELP = 4
    UNKNOWN = -1
    

def mode_to_str(mode):
    if mode == irecv.Mode.DFU_MODE:
        return 'DFU'
    elif mode in (irecv.Mode.RECOVERY_MODE_1, irecv.Mode.RECOVERY_MODE_2, irecv.Mode.RECOVERY_MODE_3, irecv.Mode.RECOVERY_MODE_4):
        return 'Recovery'
    elif mode == irecv.Mode.WTF_MODE:
        return 'WTF'
    else:
        return 'Unknown'

def parse_command(cmd):
    is_cmd = False
    if cmd.startswith('/'):
        is_cmd = True
    if is_cmd:
        cmd_arr = cmd.split(' ')
        if cmd_arr[0] == '/upload':
            return CommandType.UPLOAD, cmd_arr
        elif cmd_arr[0] == '/deviceinfo':
            return CommandType.DEVINFO, cmd_arr
        elif cmd_arr[0] == '/help':
            return CommandType.HELP, cmd_arr
        elif cmd_arr[0] == '/exit':
            return CommandType.EXIT, cmd_arr
        return CommandType.UNKNOWN, cmd_arr
    else:
        return 0, None

def irecv_receive(client):
    while True:
        client._device.set_interface_altsetting(1, 1)
        try:
            ret = bytearray(client._device.read(0x81, BUFFER_SIZE, 500))
        except:
            break
        client._device.set_interface_altsetting(0, 0)
        click.echo(ret.decode())

def is_breq_command(cmd):
    return cmd in ('go', 'bootx', 'reboot', 'reset', 'memboot')

def shell_init(client):
    # load history
    if client.mode not in (irecv.Mode.RECOVERY_MODE_1, irecv.Mode.RECOVERY_MODE_2, irecv.Mode.RECOVERY_MODE_3, irecv.Mode.RECOVERY_MODE_4):
        click.secho('[ERROR] Device is not in Recovery Mode, cannot start Recovery shell', fg='red')
        return -1
    while True:
            try:
                irecv_receive(client)
                cmd = input("> ")
                cmd_list = list(cmd)
                # Remove spaces at the beginning of cmd
                i = 0
                while cmd_list[i] == ' ':
                    cmd_list[i] = ''
                    i += 1
                cmd = ''.join(cmd_list)
                ret, cmd_arr = parse_command(cmd)
                if ret == 0:
                    try:
                        # TODO: Remove the necessary of reset() before sending command
                        client.reset()
                        client.send_command(cmd, b_request=1 if is_breq_command(cmd) else 0)
                    except:
                        pass
                else:
                    if ret == CommandType.UPLOAD:
                        try:
                            cmd_arr[1]
                            with open(cmd_arr[1], 'rb') as f:
                                data = f.read()
                        except:
                            click.secho(f'[ERROR] Invalid file path', fg='red')
                        client.send_buffer(data)
                    elif ret == CommandType.DEVINFO:
                        print_device_info(client)
                    elif ret == CommandType.HELP:
                        click.echo(SHELL_USAGE)
                    elif ret == CommandType.EXIT:
                        break
                    else:
                        click.echo('Invalid usage!')
                        click.echo(SHELL_USAGE)
            except Exception as e:
                print(e)

def print_device_info(client):
    click.echo(f'CPID: {hex(client.chip_id)}')
    cprv = client._device_info['CPRV']
    click.echo(f'CPRV: 0x{cprv}')
    click.echo(f'BDID: {hex(client.board_id)}')
    click.echo(f'ECID: {hex(client.ecid)}')
    cpfm = client._device_info['CPFM']
    click.echo(f'CPFM: 0x{cpfm}')
    scep = client._device_info['SCEP']
    click.echo(f'SCEP: 0x{scep}')
    ibfl = client._device_info['IBFL']
    click.echo(f'IBFL: 0x{ibfl}')
    try:
        srtg = client._device_info['SRTG']
        click.echo(f'SRTG: {srtg}')
    except:
        click.echo('SRTG: N/A')
    try:
        srnm = client._device_info['SRNM']
        click.echo(f'SRNM: {srnm}')
    except:
        click.echo('SRNM: N/A')
    try:
        imei = client._device_info['IMEI']
        click.echo(f'IMEI: {imei}')
    except:
        click.echo('IMEI: N/A')
    try:
        ap_nonce = binascii.hexlify(client.ap_nonce)
        click.echo(f'NONC: {ap_nonce.decode()}')
    except:
        click.echo('NONC: N/A')
    try:
        sep_nonce = binascii.hexlify(client.sep_nonce)
        click.echo(f'SNON: {sep_nonce.decode()}')
    except:
        click.echo('SNON: N/A')
    try:
        pwned = (client._device_info['PWND']).replace('[', '')
        pwned = pwned.replace(']', '')
        click.echo(f'PWND: {pwned}')
    except:
        pass

    click.echo(f'MODE: {mode_to_str(client.mode)}')
    for device in irecv_devices.IRECV_DEVICES:
        if device.chip_id == client.chip_id and device.board_id == client.board_id:
            click.echo(f'PRODUCT: {device.product_type}')
            click.echo(f'MODEL: {device.hardware_model}')
            click.echo(f'NAME: {device.display_name}')

# -- CLI --

@click.command()
@click.option(
    '-f',
    '--file',
    'infile',
    type=click.File('rb'),
    required=False,
    help='Send file to device'
)

@click.option(
    '-n',
    '--reboot',
    is_flag=True,
    help='Reboot device into Normal mode (exit Recovery loop)'
)

@click.option(
    '-r',
    '--reset',
    is_flag=True,
    help='Reset client'
)

@click.option(
    '-c',
    '--command',
    required=False,
    help='Send command to device'
)

@click.option(
    '-q',
    '--query',
    is_flag=True,
    help='Query device info'
)

@click.option(
    '-s',
    '--shell',
    is_flag=True,
    help='Start an interactive shell'
)

@click.option(
    '-m',
    '--mode',
    is_flag=True,
    help='Print device\'s current mode'
)

def main(infile, reboot, command, shell, mode, query, reset):
    if len(sys.argv) == 1:
        main(['--help'])

    client = None
    try:
        client = irecv.IRecv(timeout=5)
    except IRecvNoDeviceConnectedError:
        click.secho('[ERROR] Unable to connect to device', fg='red')
        return -1
    except Exception as e:
        click.secho(f'[ERROR] Could not init IRecv client {str(e)}', fg='red')
        return -1

    if infile:
        data = infile.read()
        try:
            client.send_buffer(data)
        except PyMobileDevice3Exception as e:
            return -1
        return 0
    elif reboot:
        client.set_autoboot(1)
        client.reboot()
        return 0
    elif command:
        try:
            client.send_command(command)
        except Exception as e:
            click.secho(f'[WARNING] Caught exception: {e}', fg='yellow')
        return 0
    elif shell:
        return shell_init(client)
    elif query:
        print_device_info(client)
        return 0
    elif mode:
        click.echo(f'{mode_to_str(client.mode)} Mode')
    elif reset:
        client.reset()
        return 0

main.context_settings = dict(help_option_names=['-h', '--help'])
