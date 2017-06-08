# Delphi-unit-OpenSSL
#
#  migrate from http://www.disi.unige.it/person/FerranteM/delphiopenssl/
#  Author FerranteM

Delphi import unit for OpenSSL DLL

OpenSSL is a collaborative project to develop an Open Source toolkit implementing the Secure Sockets Layer (SSL v2/v3) and Transport Layer Security (TLS v1) protocols as well as a full-strength general purpose cryptography library.
To use OpenSSL software on Microsoft Windows 32 bit systems, you can get DDLs from the GNU Win32 project site.
Borland Delphi and OpenSSL

Delphi can use OpenSSL library invoking DLL.
OpenSSL toolkit is divided in two modules: libssl, implementing SSLv2/v3 and TLS for network communications and libcrypto, that implements cryptography functions.
To use SLv2/v3 and TLS network function with Delphi, you can use components from Indy project.
CSITA has developed a unit to import some function about X.509 certificate.
Required files

Gnu Win32 libeay32.dll
    OpenSSL DLL. Present unit has been developed for 0.9.6b version. Version 0.9.6g compiled by Intelicom for Indy project seem to work correctly; 
libeay32.pas v. 0.7m
    DLL functions prototypes. Not all libeay32.dll functions have a prototype there; all functions that use C-style file pointer are not defined;

    What's new in 0.7m version, 05/11/2010

        typos and bugs fixes
        added support for PCKS#8 functions (contributed by Luis Carrasco - Bambu Code, Mexico)
        redefinition of PChar as PCharacter to handle PChar and PAnsiChar types

    What's new in 0.7d version, 12/15/2006

        typos and bugs fixes
        removed EVP_MD_size and EVP_MD_CTX_size: these functions are not defined in DLL and handle their parameter in a non-opaque way.
        add BIGNUM functions
        between 0.9.6h and 0.9.7, OpenSSL project splits OpenSSL_add_all_algorithms in two new functions. Some versions of libeay32.dll use old name, some use new one. See http://www.openssl.org/news/changelog.html In this unit, OpenSSL_add_all_algorithms is now a wrapper that dynamically loads appropriate function from DLL.

    What's new in 0.7 version, 09/14/2006

        bug fix (thanks to M. Hlavac and R. Tamme)
        funzioni di gestione della memoria
        funzioni di gestione diretta dei file

    What's new in 0.6 version, 07/15/2003

        fixed some record type (EVP_MD, EVP_MD_CTX, etc...)
        new function prototipes 

    What's new in 0.4 version, 03/17/2003

        renamed libeay32.pas
        some small bug fixed
        several new function prototipes defined 

OpenSSLUtils.pas v. 0.5
    Utility functions and classes. This unit is a "technological exercise" and not a production grade component.
    New in 0.5 version, 06/01/2010

        Thanks to Pablo Romero (Cordoba, Argentina) now compile on Delphi 2006, 2007, 2009 and 2010

    New examples in 0.3 version, 03/24/2003

        new TPKCS7 class for PCKS#7 envelope reading
        new TX509Certificate class for X.509 certificate verifing
        some new function 

Functions documentation are included with OpenSSL distribution.

Examples

    How to get OpenSSL DDL version DLL
    How to compute SHA1 digest
    Generate a RSA keypair (coded in OpenSSLUtils)
    S/MIME sign (coded in OpenSSLUtils)
    How to extract a PKCS#7 envelop content (coded in OpenSSLUtils)
    How to verify a PKCS#7 envelop (coded in OpenSSLUtils)
    Loading a private key, ask for passphrase with callback
    File encryption using a RSA private key
    RSA+MD5 signature

Comments

Any suggestion, contribution and comment are appreciated. You can write to marco@csita.unige.it