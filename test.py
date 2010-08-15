#!/usr/bin/python2.5
# -*- coding: utf-8 -*-
# Copyright © 2010 Andrew D. Yates
# All Rights Reserved
"""Sanity test for xmldsig."""
___authors__ = '"Andrew D. Yates" <andrew.yates@hhmds.com>'


import __init__ as top


def main():
  """Sign and verify a sample SAML XML response with trivial keys.

  Raises:
    AssertionError: sign and verify test failed
  """
  # trivial inverse function pair
  private = public = lambda x: x
  
  xml = '<samlp:Response xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="123"></samlp:Response>'
  mod = '\x00'*128
  exp = '\x03'
  
  signed_xml = top.sign(xml, private, mod, exp)
  is_verified = top.verify(signed_xml, public, mod)
  
  assert(is_verified)

  
if __name__ == '__main__':
  main()
