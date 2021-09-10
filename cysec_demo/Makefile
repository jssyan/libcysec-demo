# Compiler settings
CC      = $(CROSS_COMPILE)gcc
CFLAGS  = -g -I. -D_REENTRANT -D_GNU_SOURCE -fPIC -I../include -I${CYSEC_ROOTDIR}/include $(CCFLAGS)
LDFLAGS = $(LLDFLAGS) -L${CYSEC_ROOTDIR}/lib -L${CYSEC_ROOTDIR}
LIBS = $(LLIBS)  -lcysec
TEST_LIBS = $(LIBS)
RM     = rm -f

STRIP  = $(CROSS_COMPILE)strip

# Implicit rules

SUFFIXES = .o .c .h .a .so .sl

COMPILE.c=$(CC) $(CFLAGS)  -c
.c.o:
	@(echo "compiling $< ...")
	($(COMPILE.c) -o $@ $(CFLAGS) $<)

TARGET1 = demo_sc
SRCS1 = demo_sc.c util.c
OBJS1 = $(SRCS1:.c=.o)

TARGET2 = demo_lc
SRCS2 = demo_lc.c util.c
OBJS2 = $(SRCS2:.c=.o)

ifndef CYSEC_NO_DIGEST
TEST_DIGEST=test_digest
TEST_DIGEST_SRC=test_digest.c  test_util.c 
TEST_DIGEST_OBJ=$(TEST_DIGEST_SRC:.c=.o)
else
TEST_DIGEST=
endif

ifndef CYSEC_NO_HMAC
TEST_HMAC=test_hmac
TEST_HMAC_SRC=test_hmac.c test_util.c
TEST_HMAC_OBJ=$(TEST_HMAC_SRC:.c=.o)
else
TEST_HMAC=
endif

ifndef CYSEC_NO_CIPHER
TEST_CIPHER=test_cipher
TEST_CIPHER_SRC=test_cipher.c test_util.c
TEST_CIPHER_OBJ=$(TEST_CIPHER_SRC:.c=.o)
else
TEST_CIPHER=
endif

ifndef CYSEC_NO_X509_REQ
TEST_CSR=test_csr
TEST_CSR_SRC= test_csr.c test_util.c
TEST_CSR_OBJ=$(TEST_CSR_SRC:.c=.o)
else
TEST_CSR=
endif

TEST_MGR= test_mgr
TEST_MGR_SRC= test_mgr.c test_util.c
TEST_MGR_OBJ=$(TEST_MGR_SRC:.c=.o)

ifndef CYSEC_NO_OCSP
TEST_OCSP= test_ocsp
TEST_OCSP_SRC= test_ocsp.c test_util.c
TEST_OCSP_OBJ=$(TEST_OCSP_SRC:.c=.o)
else
TEST_OCSP=
endif

ifndef CYSEC_NO_PKCS7
TEST_PKCS7= test_pkcs7
TEST_PKCS7_SRC= test_pkcs7.c test_util.c
TEST_PKCS7_OBJ=$(TEST_PKCS7_SRC:.c=.o)
else
TEST_PKCS7=
endif

TEST_PKEY= test_pkey
TEST_PKEY_SRC= test_pkey.c test_util.c
TEST_PKEY_OBJ=$(TEST_PKEY_SRC:.c=.o)

ifndef CYSEC_NO_SCEP
TEST_SCEP_PKCSREQ=test_scep_pkcsreq
TEST_SCEP_PKCSREQ_SRC=test_scep_pkcsreq.c test_util.c
TEST_SCEP_PKCSREQ_OBJ=$(TEST_SCEP_PKCSREQ_SRC:.c=.o)
endif

ifndef CYSEC_NO_TLS
TEST_TLS= test_tls
TEST_TLS_SRC=test_tls.c test_util.c
TEST_TLS_OBJ=$(TEST_TLS_SRC:.c=.o)
else
TEST_TLS=
endif

ifndef CYSEC_NO_ASN1
TEST_ASN1= test_asn1
TEST_ASN1_SRC= test_asn1.c test_util.c
TEST_ASN1_OBJ=$(TEST_ASN1_SRC:.c=.o)
else
TEST_ASN1=
endif

TEST_PKEY_PAIR_CHECK=test_pkey_pair_check
TEST_PKEY_PAIR_CHECK_SRC=test_pkey_pair_check.c test_util.c
TEST_PKEY_PAIR_CHECK_OBJ=$(TEST_PKEY_PAIR_CHECK_SRC:.c=.o)

ifndef CYSEC_NO_PKCS5
TEST_PBES=test_pbes
TEST_PBES_SRC=test_pbes.c test_util.c
TEST_PBES_OBJ=$(TEST_PBES_SRC:.c=.o)
else
TEST_PBES=
endif

TEST_CRT=test_crt
TEST_CRT_SRC= test_crt.c test_util.c
TEST_CRT_OBJ=$(TEST_CRT_SRC:.c=.o)

all: $(TARGET1) $(TARGET2)  $(TEST_DIGEST) $(TEST_HMAC) $(TEST_CIPHER) $(TEST_CSR) $(TEST_MGR) $(TEST_OCSP) $(TEST_PKCS7) $(TEST_PKEY) \
	$(TEST_SCEP_PKCSREQ)  $(TEST_TLS) $(TEST_ASN1) $(TEST_PKEY_PAIR_CHECK) $(TEST_PBES) $(TEST_CRT)

$(TARGET1) : $(OBJS1)
	$(CC) -o $(TARGET1) $(OBJS1) $(CFLAGS) $(CCFLAGS) $(LDFLAGS) $(LIBDIR) -lm -L../lib $(LIBS)
	#$(STRIP) $(TARGET1)

$(TARGET2) : $(OBJS2)
	$(CC) -o $(TARGET2) $(OBJS2) $(CFLAGS) $(CCFLAGS) $(LDFLAGS) $(LIBDIR) -lm -L../lib $(LIBS)
	#$(STRIP) $(TARGET2)

test_digest: $(TEST_DIGEST_OBJ)
	$(CC) -o $@ $(TEST_DIGEST_OBJ) $(CFLAGS) $(CCFLAGS) $(LDFLAGS) $(LIBDIR) -L./ $(TEST_LIBS)

test_hmac:  $(TEST_HMAC_OBJ)
	$(CC) -o $@ $(TEST_HMAC_OBJ) $(CFLAGS) $(CCFLAGS) $(LDFLAGS) $(LIBDIR) -L./ $(TEST_LIBS)

test_cipher: $(TEST_CIPHER_OBJ) 
	$(CC) -o $@ $(TEST_CIPHER_OBJ) $(CFLAGS) $(CCFLAGS) $(LDFLAGS) $(LIBDIR) -L./ $(TEST_LIBS)

test_csr: $(TEST_CSR_OBJ)
	$(CC) -o $@ $(TEST_CSR_OBJ) $(CFLAGS) $(CCFLAGS) $(LDFLAGS) $(LIBDIR) -L./ $(TEST_LIBS)

test_mgr: $(TEST_MGR_OBJ)
	$(CC) -o $@ $(TEST_MGR_OBJ) $(CFLAGS) $(CCFLAGS) $(LDFLAGS) $(LIBDIR) -L./ $(TEST_LIBS)

test_ocsp: $(TEST_OCSP_OBJ)
	$(CC) -o $@ $(TEST_OCSP_OBJ) $(CFLAGS) $(CCFLAGS) $(LDFLAGS) $(LIBDIR) -L./ $(TEST_LIBS)

test_pkcs7:  $(TEST_PKCS7_OBJ)
	$(CC) -o $@ $(TEST_PKCS7_OBJ) $(CFLAGS) $(CCFLAGS) $(LDFLAGS) $(LIBDIR) -L./ $(TEST_LIBS)

test_pkey:  $(TEST_PKEY_OBJ)
	$(CC) -o $@ $(TEST_PKEY_OBJ) $(CFLAGS) $(CCFLAGS) $(LDFLAGS) $(LIBDIR) -L./ $(TEST_LIBS)

test_scep_pkcsreq:  $(TEST_SCEP_PKCSREQ_OBJ)
	$(CC) -o $@ $(TEST_SCEP_PKCSREQ_OBJ) $(CFLAGS) $(CCFLAGS) $(LDFLAGS) $(LIBDIR) -L./ $(TEST_LIBS)

test_scep_renewalreq:  $(TEST_SCEP_RENEWALREQ_OBJ)
	$(CC) -o $@ $(TEST_SCEP_RENEWALREQ_OBJ) $(CFLAGS) $(CCFLAGS) $(LDFLAGS) $(LIBDIR) -L./ $(TEST_LIBS)

test_tls:  $(TEST_TLS_OBJ)
	$(CC) -o $@ $(TEST_TLS_OBJ) $(CFLAGS) $(CCFLAGS) $(LDFLAGS) $(LIBDIR) -L./ $(TEST_LIBS)

test_asn1:  $(TEST_ASN1_OBJ)
	$(CC) -o $@ $(TEST_ASN1_OBJ) $(CFLAGS) $(CCFLAGS) $(LDFLAGS) $(LIBDIR) -L./ $(TEST_LIBS)

test_pkey_pair_check: $(TEST_PKEY_PAIR_CHECK_OBJ)
	$(CC) -o $@ $(TEST_PKEY_PAIR_CHECK_OBJ) $(CFLAGS) $(CCFLAGS) $(LDFLAGS) $(LIBDIR) -L./ $(TEST_LIBS)

test_pbes: $(TEST_PBES_OBJ)
	$(CC) -o $@ $(TEST_PBES_OBJ) $(CFLAGS) $(CCFLAGS) $(LDFLAGS) $(LIBDIR) -L./ $(TEST_LIBS)

test_crt: $(TEST_CRT_OBJ)
	$(CC) -o $@ $(TEST_CRT_OBJ) $(CFLAGS) $(CCFLAGS) $(LDFLAGS) $(LIBDIR) -L./ $(TEST_LIBS)

clean:
	rm -f $(TARGET1) $(TARGET2)  $(TEST_DIGEST) $(TEST_HMAC) $(TEST_CIPHER) $(TEST_CSR) $(TEST_MGR) $(TEST_OCSP) $(TEST_PKCS7) $(TEST_PKEY) \
	$(TEST_SCEP_PKCSREQ)  $(TEST_TLS) $(TEST_ASN1) $(TEST_PKEY_PAIR_CHECK) $(TEST_PBES) $(TEST_CRT)
	rm -f *.o
