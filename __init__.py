#!/usr/bin/python2.5
# -*- coding: utf-8 -*-
# Copyright © 2010 Andrew D. Yates
# All Rights Reserved
"""XMLDSig: Sign and Verify XML digital cryptographic signatures.

xmldsig is a minimal implementation of bytestring cryptographic
digital signatures which I have written to handle the Google
Application Single Sign On service in Security Assertion Markup
Language. (Google Apps, SSO, SAML respectively). 

XMLDSIG is a ridiculous but necessary protocol for identification and
authentication in computer systems. Why is XMLDSIG ridiculous? The
defining feature of XML is that its exact bytestring of the message is
arbitrary. The defining feature of a cryptographic signature is that
the exact bytestring of the message is critical. Only by what I can
imagine to be some "practical man's" increasingly pathetic sophistry
to assert himself over the ideas which he derides as "of no practical
importance" could two such elegant ideas be so crudely forced together
and then ---with so much energy--- propped, pushed, and defended.

In this module, all XML must be in Bytestring XML Format:

Bytestring XML Format
=====================
* XML is a utf-8 encoded bytestring.
* XML namespaces must explicitly define all xmlns prefix names
* XML is in minimum whitespace representation.
* <Signature> always signs the entire xml string
* signed XML must be in "Canonicalization" (c14n) form
  see: http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments
* <Signature> is always enveloped as the first child of root
  see: http://www.w3.org/2000/09/xmldsig#enveloped-signature

Note that whitespace, character case, and encoding are significant in
Bytestring XML: e.g. "<b>text</b>" is not the same as "<b> text</b>".

References
==========
* [DI]
  http://www.di-mgt.com.au/xmldsig.html
  Signing an XML document using XMLDSIG
* [RFC 2437]
  http://www.ietf.org/rfc/rfc2437.txt
  PKCS #1: RSA Cryptography Specifications
* [RFC 3275]
  http://www.ietf.org/rfc/rfc3275.txt
  (Extensible Markup Language) XML-Signature Syntax and Processing
* [RSA-SHA1]
  http://www.w3.org/TR/2008/REC-xmldsig-core-20080610/#sec-PKCS1
  XML Signature Syntax and Processing (Second Edition)
  Section: 6.4.2 PKCS1 (RSA-SHA1)
"""

import hashlib
import re


RX_ROOT = re.compile('<[^> ]+ ?([^>]*)>')
RX_NS = re.compile('xmlns:[^> ]+')
RX_SIGNATURE = re.compile('<Signature.*?</Signature>')
RX_SIGNED_INFO = re.compile('<SignedInfo.*?</SignedInfo>')
RX_SIG_VALUE = re.compile('<SignatureValue[^>]*>([^>]+)</SignatureValue>')

PATH = os.path.dirname(os.path.abspath(__file__))
SIGNED_INFO = os.path.join(PATH, "templates/signed_info.xml")
SIGNATURE = os.path.join(PATH, "templates/signature.xml")

# SHA1 digest with ASN.1 BER SHA1 algorithm designator prefix [RSA-SHA1]
PREFIX = '\x30\x21\x30\x09\x06\x05\x2B\x0E\x03\x02\x1A\x05\x00\x04\x14'

# Pattern Map:
#   xmlns_attr: xml name space definition attributes including ' ' prefix
#   digest_value: padded hash of message in base64
PTN_SIGNED_INFO_XML = \
'<SignedInfo xmlns="http://www.w3.org/2000/09/xmldsig#"%(xmlns_attr)s><CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments"></CanonicalizationMethod><SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"></SignatureMethod><Reference URI=""><Transforms><Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"></Transform></Transforms><DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"></DigestMethod><DigestValue>%(digest_value)s</DigestValue></Reference></SignedInfo>'

# Pattern Map:
#   signed_info_xml: <SignedInfo> bytestring xml
#   signature_value: computed signature from <SignedInfo> in base64
#   modulus: signing RSA key modulus in base64 
#   exponent: signing RSA key exponent in base64
PTN_SIGNATURE_XML = \
'<Signature xmlns="http://www.w3.org/2000/09/xmldsig#">%(signed_info_xml)s<SignatureValue>%(signature_value)s</SignatureValue><KeyInfo><KeyValue><RSAKeyValue><Modulus>%(modulus)s</Modulus><Exponent>%(exponent)s</Exponent></RSAKeyValue></KeyValue></KeyInfo></Signature>'

b64e = lambda s: s.encode('base64').strip() 
b64d = lambda s: s.decode('base64').strip() 


def sign(xml, f_private, modulus, exponent):
  """Return xmldsig XML string from xml_string of XML.

  Args:
    xml: str of bytestring xml to sign
    f_private: func 
    modulus: str
    exponent: str
  Returns:
    str: signed bytestring xml
  """
  signed_info_xml = _signed_info(xml)
  signed = _signed_value(signed_info_xml, len(modulus))
  signature_value = f_private(signed)

  signature_xml = PTN_SIGNATURE_XML % {
    'signed_info_xml': signed_info_xml,
    'signature_value': b64e(signature_value),
    'modulus': b64e(modulus),
    'exponent': b64e(exponent),
  }
  # insert xmldsig after first '>' in message
  signed_xml = xml.replace('>', '>'+signature_xml, 1)
  
  return signed_xml


def verify(xml, f_public, modulus):
  """Return if <Signature> in `xml` matches `xml` with `key`.
  
  Args:
    xml: str of XML with xmldsig <Signature> element
    f_public: func
    modulus: str
  Returns:
    bool: signature for `xml` is valid
  """
  signature = RX_SIGNATURE.search(xml).group(0)
  unsigned_xml = xml.replace(signature, '')
  
  # retreive the signed value in `xml` using `key`
  signature_value = RX_SIG_VALUE.search(signature).group(1)
  expected = f_public(b64d(signature_value))
  
  # compute the actual signed value for `xml`
  signed_info_xml = _signed_info(unsigned_xml)
  actual = _signed_value(signed_info_xml, len(modulus))
  
  return expected == actual


def _digest(data):
  """SHA1 hash digest of message data.
  
  Implements RFC2437, 9.2.1 EMSA-PKCS1-v1_5, Step 1. for "Hash = SHA1"
  
  Args:
    data: str of bytes to digest
  Returns:
    str: of bytes of digest from `data`
  """
  hasher = hashlib.sha1()
  hasher.update(data)
  return hasher.digest()


def _get_xmlns_prefixes(xml):
  """Return string of root namespace prefix attributes in given order.
  
  Args:
    xml: str of bytestring xml
  Returns:
    str: [xmlns:prefix="uri"] list ordered as in `xml`
  """
  root_attr = RX_ROOT.match(xml).group(1)
  ns_attrs = [a for a in root_attr.split(' ') if RX_NS.match(a)]
  return ' '.join(ns_attrs)


def _signed_info(xml):
  """Return <SignedInfo> for bytestring xml.

  Args:
    xml: str of bytestring
  Returns:
    str: xml bytestring of <SignedInfo> computed from `xml`
  """
  xmlns_attr = _get_xmlns_prefixes(xml)
  if xmlns_attr:
    ' %s' % xmlns_attr

  signed_info_xml = PTN_SIGNED_INFO_XML % {
    'xmlns_attr': xmlns_attr,
    'digest_value': b64e(_digest(xml)),
  }
  return signed_info_xml


def _signed_value(data, key_size):
  """Return unencrypted rsa-sha1 signature value `padded_digest` from `data`.
  
  The resulting signed value will be in the form:
  (01 | FF* | 00 | prefix | digest) [RSA-SHA1]
  where "digest" is of the generated c14n xml for <SignedInfo>.
  
  Args:
    data: str of bytes to sign
    key_size: int of number of bytes in crytographic key
  Returns:
    str: rsa-sha1 signature value of `data`
  """
  asn_digest = PREFIX + _digest(data)
  
  # Pad to "one octet shorter than the RSA modulus" [RSA-SHA1]
  padded_size = key_size - 1
  pad_size = padded_size - len(asn_digest) - 2
  pad = '\x01' + '\xFF' * pad_size + '\x00'
  padded_digest = pad + asn_digest

  return padded_digest

