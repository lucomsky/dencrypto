#!/usr/bin/env python
# -*- coding: utf-8 -*-

import click
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import scrypt
from Crypto.Util.Padding import pad, unpad
import base64


def derive_key(passphrase, salt, key_length=32, iterations=100000):
    return scrypt(passphrase, salt, key_length, N=2**14, r=8, p=1)


@click.group()
def cli():
    ...


@cli.command()
@click.option('--data', type=str, required=True, prompt=True)
@click.option('--passphrase', type=str, required=True, prompt=True, hide_input=True)
def encrypt(data, passphrase):
    salt = get_random_bytes(16)  # 16 bytes salt
    key = derive_key(passphrase, salt)
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(data.encode('utf-8'), AES.block_size))
    iv = cipher.iv
    click.echo(base64.b64encode(salt + iv + ct_bytes).decode('utf-8'))


@cli.command()
@click.option('--enc_data', type=str, help='Base64 encoded data', required=True, prompt=True)
@click.option('--passphrase', type=str, required=True, prompt=True, hide_input=True)
def decrypt(enc_data, passphrase):
    enc_data = base64.b64decode(enc_data)
    salt = enc_data[:16]
    iv = enc_data[16:32]
    ct = enc_data[32:]
    key = derive_key(passphrase, salt)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ct), AES.block_size)
    click.echo(pt.decode('utf-8'))


if __name__ == '__main__':
    cli()
