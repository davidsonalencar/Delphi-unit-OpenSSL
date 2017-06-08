#Delphi import unit per OpenSSL DLL
##How to get OpenSSL DDL version
```
function GetVersion: string;
var
  v: cardinal;
  s: PChar;
begin
v := SSLeay;
s := SSLeay_version(_SSLEAY_CFLAGS);
result := s + ' (' + IntToHex(v, 9) + ')';
end;
```

Result is described in OPENSSL_VERSION_NUMBER(3) man page


##How to compute SHA1 digest

```
function SHA1(msg: string): string;
var
  mdLength, b64Length: integer;
  mdValue: array [0..EVP_MAX_MD_SIZE] of byte;
  mdctx: EVP_MD_CTX;
  memout, b64: pBIO;
  inbuf, outbuf: array [0..1023] of char;
begin
StrPCopy(inbuf, msg);
EVP_DigestInit(@mdctx, EVP_sha1());
EVP_DigestUpdate(@mdctx, @inbuf, StrLen(inbuf));
EVP_DigestFinal(@mdctx, @mdValue, mdLength);
mdLength := EVP_MD_CTX_size(@mdctx);
b64 := BIO_new(BIO_f_base64);
memout := BIO_new(BIO_s_mem);
b64 := BIO_push(b64, memout);
BIO_write(b64, @mdValue, mdLength);
BIO_flush(b64);
b64Length := BIO_read(memout, @outbuf, 1024);
outbuf[b64Length-1] := #0;
result := StrPas(@outbuf);
end;
```

##Generate a RSA keypair
```
procedure GenerateKeyPair;
var
  kp: TKeyPairGenerator;
begin
kp := TKeyPairGenerator.Create;
kp.KeyFileNames('c:\temp\mykeys');  // it create a pair c:\temp\mykeys.key
                                    // and c:\temp\mykeys.pub
kp.Password := 'mypasswd';          // Required
kp.GenerateRSA;
end;

Ecco il frammento di OpenSSLUtils.pas
This is the OpenSSLUtils.pas snippet

procedure TKeyPairGenerator.GenerateRSA;
var
  rsa: pRSA;
  PrivateKeyOut, PublicKeyOut, ErrMsg: pBIO;
  buff: array [0..1023] of char;
  enc: pEVP_CIPHER;
begin
if (fPrivateKeyFile = '') or (fPublicKeyFile = '') then
  raise EOpenSSL.Create('Key filenames must be specified.');
if (fPassword = '') then
  raise EOpenSSL.Create('A password must be specified.');

ERR_load_crypto_strings;
OpenSSL_add_all_ciphers;

enc := EVP_des_ede3_cbc;

// Load a pseudo random file
RAND_load_file(PChar(fSeedFile), -1);

rsa := RSA_generate_key(fKeyLength, RSA_F4, nil, ErrMsg);
if rsa=nil then
  begin
  BIO_reset(ErrMsg);
  BIO_read(ErrMsg, @buff, 1024);
  raise EOpenSSL.Create(PChar(@buff));
  end;

PrivateKeyOut := BIO_new(BIO_s_file());
BIO_write_filename(PrivateKeyOut, PChar(fPrivateKeyFile));
PublicKeyOut := BIO_new(BIO_s_file());
BIO_write_filename(PublicKeyOut, PChar(fPublicKeyFile));

PEM_write_bio_RSAPrivateKey(PrivateKeyOut, rsa, enc, nil, 0, nil, PChar(fPassword));
PEM_write_bio_RSAPublicKey(PublicKeyOut, rsa);

if rsa <> nil then RSA_free(rsa);
if PrivateKeyOut <> nil then BIO_free_all(PrivateKeyOut);
if PublicKeyOut <> nil then BIO_free_all(PublicKeyOut);
end;
```
##S/MIME message signing Firma S/MIME di un messaggio

Richiede OpenSSLUtils.pas
Require OpenSSLUtils.pas
```
procedure Sign: string;
var
  signer: TMessageSigner;
begin
signer := TMessageSigner.Create;
signer.LoadPrivateKey('h:\user.key', 'userpw');
signer.LoadCertificate('h:\user.crt');
signer.PlainMessage := 'Hello world.';
signer.MIMESign;
result := signer.SignedMessage;
end;
```
Ecco il frammento di OpenSSLUtils.pas
This is the OpenSSLUtils.pas snippet
```
procedure TMessageSigner.MIMESign;
var
  p7: pPKCS7;
  msgin, msgout: pBIO;
  buff: PChar;
  buffsize: integer;
begin

// Load private key if filename is defined
if fKey = nil then
  begin
  if fPrivateKeyFile <> '' then
    LoadPrivateKey(fPrivateKeyFile, fPassword)
  else
    raise EOpenSSL.Create('Private key is required.');
  end;

// load signer certificate
if fCertificate = nil then
  begin
  if fPrivateKeyFile <> '' then
    LoadCertificate(fCertificateFile)
  else
    raise EOpenSSL.Create('Signer certificate is required.');
  end;

msgin := BIO_new_mem_buf(PChar(fMessage), -1);
msgout := BIO_new(BIO_s_mem);
p7 := PKCS7_sign(fCertificate, fKey, fOtherCertificates, msgin, PKCS7_DETACHED);
BIO_reset(msgin);
SMIME_write_PKCS7(msgout, p7, msgin, PKCS7_TEXT or PKCS7_DETACHED);
// Count used byte
buffsize := BIO_pending(msgout);
GetMem(buff, buffsize+1);
BIO_read(msgout, buff, buffsize);
fSignedMessage := StrPas(buff);
FreeMem(buff);
end;
```
##How to extract a PKCS#7 envelop content

Require OpenSSLUtils.pas
```
program PKCS7;

uses OpenSSLUtils;

var
  infile, outfile: String;

procedure ExtractPKCS7File(InFilename, OutFilename: String);
var
  reader: TPKCS7;
begin
reader := TPKCS7.Create;
reader.Open(InFilename);
reader.SaveContent(OutFileName);
reader.Free;
end;

begin
AppStartup;   // init crypto function
infile := 'envelope.pdf.p7m';
outfile := 'content.pdf';
ExtractPKCS7File(infile, outfile);
end.
```
Ecco il frammento di OpenSSLUtils.pas
This is the OpenSSLUtils.pas snippet
```
// Open a PKCS7 file
procedure TPKCS7.Open(Filename: string);
var
  p7file: pBIO;
  objectType: integer;
begin
p7file := BIO_new(BIO_s_file());
if p7file = nil then
  raise EOpenSSL.Create('Unable to create a file handle.');
BIO_read_filename(p7file, PChar(Filename));
if (fEncoding = auto) or (fEncoding = DER) then
  begin
  fPkcs7 := d2i_PKCS7_bio(p7file, nil);
  if (fPkcs7 = nil) and (fEncoding = auto) then
    BIO_reset(p7file);
  end;
if ((fPkcs7 = nil) and (fEncoding = auto)) or (fEncoding = PEM) then
  begin
  fPkcs7 := PEM_read_bio_PKCS7(p7file, nil, nil, nil);
  if (fPkcs7 = nil) and (fEncoding = auto) then
    BIO_reset(p7file);
  end;
if ((fPkcs7 = nil) and (fEncoding = auto)) or (fEncoding = SMIME) then
  begin
  fPkcs7 := SMIME_read_PKCS7(p7file, fDetachedData);  // &indata ????
  end;
if fPkcs7 = nil then
  raise EOpenSSL.Create('Unable to read PKCS7 file');
if p7file <> nil then
  BIO_free(p7file);
objectType := OBJ_obj2nid(fPkcs7.asn1_type);
case objectType of
  NID_pkcs7_signed: fCerts := fPkcs7.sign.cert;
  NID_pkcs7_signedAndEnveloped: fCerts := fPkcs7.signed_and_enveloped.cert;
  end;
end;

procedure TPKCS7.SaveContent(Filename: String);
var
  p7bio, contentfile: pBIO;
  sinfos: pSTACK_OFPKCS7_SIGNER_INFO;
  i: integer;
  buffer: array [0..4096] of char;
begin
if fPkcs7 = nil then
  raise EOpenSSL.Create('No PKCS7 content.');
if OBJ_obj2nid(fPkcs7.asn1_type) <> NID_pkcs7_signed then
  raise EOpenSSL.Create('Wrong PKCS7 format.');
if (PKCS7_get_detached(fPkcs7) <> nil)
    and (fDetachedData = nil) then
  raise EOpenSSL.Create('PKCS7 has no content.');
sinfos := PKCS7_get_signer_info(fPkcs7);
if (sinfos = nil) or (sk_num(sinfos) = 0) then
  raise EOpenSSL.Create('No signature data.');
contentfile := BIO_new(BIO_s_file());
if BIO_write_filename(contentfile, PChar(Filename)) <= 0 then
  raise EOpenSSL.Create('Error creating output file.');
p7bio := PKCS7_dataInit(fPkcs7, fDetachedData);
repeat
  i := BIO_read(p7bio, @buffer, SizeOf(buffer));
  if i > 0 then
    BIO_write(contentfile, @buffer, i);
until i <= 0;

if fDetachedData <> nil then
  BIO_pop(p7bio);
BIO_free_all(p7bio);
BIO_free(contentfile);
end;
```


##How to verify a PKCS#7 envelop

Require OpenSSLUtils.pas
```
program VerifyPKCS7;

uses OpenSSLUtils;

var
  infile: String;
  envelope: TPKCS7;
  CAcerts: array [0..1] of TX509Certificate;

function VerifyPKCS7(p7: TPKCS7): boolean;
begin
result := true;
try
  writeln('Documento firmato da: ' + p7.Certificate[0].Subject);  // print envelope signer
  writeln('Certificato rilasciato da: ' + p7.Certificate[0].Issuer);  // certificate issuer
  if p7.Certificate[0].IsTrusted(CAcerts) then
    writeln('Il certificato è affidabile.');  // signer certificate is trusted
  if (p7.Certificate[0].IsExpired) then
    begin
    if p7.Certificate[0].NotBefore > Time then
      writeln('Il certificato NON è valido.');  // signer cert is expired
    if p7.Certificate[0].NotAfter < Time then
      writeln('Il certificato è scaduto.');  // signer cert is not still valid
    end
  if p7.VerifyData then
    writeln('Il documento è integro.');  // data integrity check passed
except
  on EO: EOpenSSL do
    begin
    writeln('Il file non sembra essere del formato PKCS7 corretto.');  // invalid PKCS#7 file format
    result := false;
    end;
  end;
end;

begin
AppStartup;   // init crypto function
infile := 'envelope.pdf.p7m';
envelope := TPKCS7.Create;
envelope.Open(infile);
CAcerts[0] := TX509Certificate.Create;   // Carica i certificati della CA
CAcerts[0].LoadFromFile('RootCA.crt');   // Load CA certificates
CAcerts[1] := TX509Certificate.Create;
CAcerts[1].LoadFromFile('IntermediateCA.pem');
VerifyPKCS7(envelope);
CAcerts[0].Free;
CAcerts[1].Free;
envelope.Free;
end.
```

##Ask for private key passphrase with callback

Require libeay32.pas

```

(******************************************************************************
 Author: Marco Ferrante
 Copyright (C) 2002-2003, CSITA - Università di Genova (IT).
 http://www.csita.unige.it/
 ******************************************************************************)
unit main;

interface

uses
  Windows, Messages, SysUtils, Variants, Classes, Graphics, Controls, Forms,
  Dialogs, libeay32, StdCtrls;

type
  {
    Must return passphrase
  }
  TAskPassphraseEvent = procedure(var Passphrase: String) of object;

  TMainForm = class(TForm)
    Button1: TButton;
    procedure Button1Click(Sender: TObject);
  private
    { Private declarations }
    fAskPassphrase: TAskPassphraseEvent;
    procedure InitOpenSSL;
    procedure FreeOpenSSL;
    procedure AskPassphrase(var Passphrase: String);
    function ReadPrivateKey(AFileName: TFileName): pEVP_PKEY;
  public
    { Public declarations }
  end;

var
  MainForm: TMainForm;

implementation

{$R *.dfm}
{
  Return last error message
}
function GetErrorMessage: string;
var
  ErrMsg: array [0..160] of char;
begin
ERR_error_string(ERR_get_error, @ErrMsg);
result := StrPas(@ErrMsg);
end;

{
  You must call this procedure before any OpenSSL-related function.
  When you finish, you can clear environment with FreeOpenSSL prodedure.
}
procedure TMainForm.InitOpenSSL;
begin
OpenSSL_add_all_algorithms;
OpenSSL_add_all_ciphers;
OpenSSL_add_all_digests;
ERR_load_crypto_strings;
end;

{
  Cleanup environment and release memory.
}
procedure TMainForm.FreeOpenSSL;
begin
EVP_cleanup;
end;

{
  Open a dialog to ask for passphrase if required.
}
procedure TMainForm.AskPassphrase(var Passphrase: String);
begin
Passphrase := 'bar';  // Dummy example value
end;

{
  Read a private key, asking for password if required.
}
function TMainForm.ReadPrivateKey(AFileName: TFileName): pEVP_PKEY;
var
  keyfile: pBIO;

  // Callback for encrypted private key
  function cb(buffer: PChar; blength: integer;
      verify: integer; data: pointer): integer; cdecl;
  var
    Passphrase: String;
  begin
  result := 0;
  if (data = nil) or not(TObject(data) is TMainForm) then
    exit;
  if not Assigned(TMainForm(data).fAskPassphrase) then
    exit;
  TMainForm(data).fAskPassphrase(Passphrase);
  if Passphrase <> '' then
    begin
    StrPCopy(buffer, Passphrase);  // TODO: length check
    result := Length(Passphrase);
    end
  end;

begin
keyfile := BIO_new(BIO_s_file());
BIO_read_filename(keyfile, PChar(AFilename));
result := PEM_read_bio_PrivateKey(keyfile, nil, @cb, self);
if result = nil then
  raise Exception.Create('Unable to read private key. ' + GetErrorMessage);
end;

{
  Main procedure: when you press button, private key will be load
}
procedure TMainForm.Button1Click(Sender: TObject);
var
  key: pEVP_PKEY;
begin
fAskPassphrase := AskPassphrase;
InitOpenSSL;
key := ReadPrivateKey('foo.key');
FreeOpenSSL
end;

end.
```

##File encryption using a RSA private key

Require libeay32.pas, v. >= 0.7

```
// Equivalent to:
//   openssl rsautl -encrypt -in CleartextFile -out CryptedFile -inkey KeyFile
// Probably you should set padding := RSA_PKCS1_PADDING
procedure TMainForm.RSAEncrypt(KeyFile, CleartextFile, CryptedFile: string; padding: integer);
var
  rsa: pRSA;
  keysize: integer;

  key: pEVP_PKEY;
  cleartext, crypted: pBIO;
  rsa_in, rsa_out: pointer;
  rsa_inlen, rsa_outlen: integer;
begin
// as in AskPassphrase.html
key := ReadPrivateKey(KeyFile);
rsa := EVP_PKEY_get1_RSA(key);
EVP_PKEY_free(key);
if rsa = nil then
  raise Exception.Create('Error getting RSA key. ' + GetErrorMessage);

cleartext := BIO_new_file(PChar(CleartextFile), 'rb');
if cleartext = nil then
  raise Exception.Create('Error Reading Input File. ' + GetErrorMessage);
crypted := BIO_new_file(PChar(CryptedFile), 'wb');
if crypted = nil then
  raise Exception.Create('Error Reading Output File. ' + GetErrorMessage);

keysize := RSA_size(rsa);

// Should be free if exception is raised
rsa_in := OPENSSL_malloc(keysize * 2);
rsa_out := OPENSSL_malloc(keysize);

// Read the input data
rsa_inlen := BIO_read(cleartext, rsa_in, keysize * 2);
if rsa_inlen <= 0 then
  raise Exception.Create('Error reading input Data.');
rsa_outlen := RSA_public_encrypt(rsa_inlen, rsa_in, rsa_out, rsa, padding);
if rsa_outlen <= 0 then
  raise Exception.Create('RSA operation error. ' + GetErrorMessage);

BIO_write(crypted, rsa_out, rsa_outlen);
RSA_free(rsa);
BIO_free(cleartext);
BIO_free_all(crypted);
if rsa_in <> nil then
  OPENSSL_free(rsa_in);
if rsa_out <> nil then
  OPENSSL_free(rsa_out);
end;
```

##RSA+MD5 signature

A nice contribute by Dim (Russia)

Require libeay32.pas, v. >= 0.7
```
// Equivalent to:
//   openssl dgst -md5 -sign private.pem -hex -out test.hex 
function Sign_RSA_MD5(privatekey,msg: string): string;
var
Len: cardinal;
mdctx: EVP_MD_CTX;
inbuf, outbuf: array [0..1023] of char;
key: pEVP_PKEY;
begin
StrPCopy(inbuf, msg);
InitOpenSSL;
key:=ReadPrivateKey(privatekey);
EVP_SignInit(@mdctx, EVP_md5());
EVP_SignUpdate(@mdctx, @inbuf, StrLen(inbuf));
EVP_SignFinal(@mdctx, @outbuf, Len, key);
FreeOpenSSL;
BinToHex(outbuf, inbuf,Len);
inbuf[2*Len]:=#0;
result := StrPas(inbuf);
end;
```