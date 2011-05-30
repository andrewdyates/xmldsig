#!/usr/bin/python2.5
# -*- coding: utf-8 -*-
# Copyright © 2011 Andrew D. Yates
# All Rights Reserved
"""Sanity test for xmldsig."""

import unittest
import __init__ as top


# in bits
KEY_SIZE = 128
XML = '<samlp:Response xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="123"></samlp:Response>'

# trivial public key (values not used in encryption)
MOD = '\x00' * (KEY_SIZE / 8)
EXP = '\x03'

# obviously fake certificate encoding
CERT = "ABCD" * 30
SUBJECT_NAME = "DUMMY SUBJECT"

# trivial inverse function pair (identity function)
private_f = lambda x: x
public_f = lambda x: x

KEY_INFO_XML = "<KeyInfo>Dummy</KeyInfo>"
SIG_ID = "DUMMY ID 123"

# expected values for tests
EXP_KEY_INFO_XML_RSA = \
"<KeyInfo><KeyValue><RSAKeyValue><Modulus>AAAAAAAAAAAAAAAAAAAAAA==</Modulus><Exponent>Aw==</Exponent></RSAKeyValue></KeyValue></KeyInfo>"
EXP_KEY_INFO_XML_CERT = \
"<KeyInfo><X509Data><X509SubjectName>DUMMY SUBJECT</X509SubjectName><X509Certificate>ABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCD</X509Certificate></X509Data></KeyInfo>"
EXP_KEY_INFO_XML_CERT_NO_SUBJECT = \
"<KeyInfo><X509Data><X509Certificate>ABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCD</X509Certificate></X509Data></KeyInfo>"
EXP_SIGNED_XML = \
'<samlp:Response xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="123"><Signature xmlns="http://www.w3.org/2000/09/xmldsig#"><SignedInfo xmlns="http://www.w3.org/2000/09/xmldsig#" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"><CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments"></CanonicalizationMethod><SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"></SignatureMethod><Reference URI=""><Transforms><Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"></Transform></Transforms><DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"></DigestMethod><DigestValue>H7olMzu7Zog9nSS7Yl+FQ1Mp8eQ=</DigestValue></Reference></SignedInfo><SignatureValue>AQAwITAJBgUrDgMCGgUABBS2LaIdRUmFpxZc4I16PGDU0hNzEQ==</SignatureValue><KeyInfo>Dummy</KeyInfo></Signature></samlp:Response>'
EXP_SIGNED_XML_WITH_ID = \
'<samlp:Response xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="123"><Signature Id="DUMMY ID 123" xmlns="http://www.w3.org/2000/09/xmldsig#"><SignedInfo xmlns="http://www.w3.org/2000/09/xmldsig#" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"><CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments"></CanonicalizationMethod><SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"></SignatureMethod><Reference URI=""><Transforms><Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"></Transform></Transforms><DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"></DigestMethod><DigestValue>H7olMzu7Zog9nSS7Yl+FQ1Mp8eQ=</DigestValue></Reference></SignedInfo><SignatureValue>AQAwITAJBgUrDgMCGgUABBS2LaIdRUmFpxZc4I16PGDU0hNzEQ==</SignatureValue><KeyInfo>Dummy</KeyInfo></Signature></samlp:Response>'


class TestKeyInfo(unittest.TestCase):
  
  def test_key_info_xml_rsa(self):
    key_info_xml = top.key_info_xml_rsa(MOD, EXP)
    self.assertEqual(key_info_xml, EXP_KEY_INFO_XML_RSA)

  def test_key_info_xml_cert_no_subject(self):
    key_info_xml = top.key_info_xml_cert(CERT)
    self.assertEqual(key_info_xml, EXP_KEY_INFO_XML_CERT_NO_SUBJECT)

  def test_key_info_xml_cert(self):
    key_info_xml = top.key_info_xml_cert(CERT, SUBJECT_NAME)
    self.assertEqual(key_info_xml, EXP_KEY_INFO_XML_CERT)


class TestTrivialKeys(unittest.TestCase):

  def test_sign(self):
    signed_xml = top.sign(XML, private_f, KEY_INFO_XML, KEY_SIZE)
    self.assertEqual(signed_xml, EXP_SIGNED_XML)

  def test_sign_with_id(self):
    signed_xml = \
      top.sign(XML, private_f, KEY_INFO_XML, KEY_SIZE, sig_id_value=SIG_ID)
    self.assertEqual(signed_xml, EXP_SIGNED_XML_WITH_ID)

  def test_verify(self):
    signed_xml = top.sign(XML, private_f, KEY_INFO_XML, KEY_SIZE)
    is_verified = top.verify(signed_xml, public_f, KEY_SIZE)
    self.assertTrue(is_verified)

class TestB64(unittest.TestCase):

  def test_b64_hello(self):
    self.assertEqual("hello", top.b64d(top.b64e("hello")))

  def test_b64_allASCII(self):
    msg = ''.join([chr(x) for x in range(256)])
    self.assertEqual(msg, top.b64d(top.b64e(msg)))

  def test_int(self):
    num = 22
    self.assertEqual(num, ord(top.b64d(top.b64e(num))))
  
    
def main():
  unittest.main()
if __name__ == '__main__':
  main()
