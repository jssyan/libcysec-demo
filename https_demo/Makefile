# Compiler settings
CC      = $(CROSS_COMPILE)gcc
CFLAGS  = -g -I. -D_REENTRANT -D_GNU_SOURCE -fPIC -I../include $(CCFLAGS) -DHAVE_PK_CUSTOM_SUPPORT
LDFLAGS = $(LLDFLAGS)

#DO_NOT_USE_PKI_CM_CALLBACK=$(DO_NOT_USE_PKI_CM_CALLBACK)

ifndef DO_NOT_USE_PKI_CM_CALLBACK
LIBPKICM= -lpkicm 
else
LIBPKICM=
endif

LIBS = $(LLIBS) $(LIBPKICM) -lcysec -lcurl -lcares

RM     = rm -f

STRIP  = $(CROSS_COMPILE)strip

# Implicit rules

SUFFIXES = .o .c .h .a .so .sl

COMPILE.c=$(CC) $(CFLAGS) -c
.c.o:
	@(echo "compiling $< ...")
	@($(COMPILE.c) -o $@ $(CFLAGS) $<)

TARGET1 = demo1
SRCS1 = demo1.c util.c
OBJS1 = $(SRCS1:.c=.o)

TARGET2 = demo2
SRCS2 = demo2.c util.c
OBJS2 = $(SRCS2:.c=.o)

TARGET3 = demo3
SRCS3 = demo3.c util.c
OBJS3 = $(SRCS3:.c=.o)

TARGET4 = demo5
SRCS4 = demo5.c util.c
OBJS4 = $(SRCS4:.c=.o)

TARGET5 = demo6
SRCS5 = demo6.c util.c
OBJS5 = $(SRCS5:.c=.o)

TARGET6 = demo1_1
SRCS6 = demo1_1.c util.c
OBJS6 = $(SRCS6:.c=.o)

TARGET7 = demo2_1
SRCS7 = demo2_1.c util.c
OBJS7 = $(SRCS7:.c=.o)

TARGET8 = demo1_2
SRCS8 = demo1_2.c util.c
OBJS8 = $(SRCS8:.c=.o)

TARGET9 = demo2_2
SRCS9 = demo2_2.c util.c
OBJS9 = $(SRCS9:.c=.o)

TARGET10 = demo1_3
SRCS10 = demo1_3.c util.c
OBJS10 = $(SRCS10:.c=.o)

TARGET11 = demo1_4
SRCS11 = demo1_4.c util.c
OBJS11 = $(SRCS11:.c=.o)

ifndef HAVE_PK_CUSTOM_KEY
VPK_SCEP = 
else
VPK_SCEP = vpk_scep
VPK_SCEP_SRC = vpk_scep.c vpk_util.c util.c
VPK_SCEP_OBJ = $(VPK_SCEP_SRC:.c=.o)
endif

all: $(TARGET1) $(TARGET2) $(TARGET3) $(TARGET4) $(TARGET5) $(TARGET6) $(TARGET8) $(TARGET9) $(TARGET10) \
	$(TARGET11)  $(VPK_SCEP)

$(TARGET1) : $(OBJS1)
	$(CC) -o $(TARGET1) $(OBJS1) $(CFLAGS) $(CCFLAGS) $(LDFLAGS) $(LIBDIR) -lm -L../lib $(LIBS)
	#$(STRIP) $(TARGET1)

$(TARGET2) : $(OBJS2)
	$(CC) -o $(TARGET2) $(OBJS2) $(CFLAGS) $(CCFLAGS) $(LDFLAGS) $(LIBDIR) -lm -L../lib $(LIBS)
	#$(STRIP) $(TARGET2)

$(TARGET3) : $(OBJS3)
	$(CC) -o $(TARGET3) $(OBJS3) $(CFLAGS) $(CCFLAGS) $(LDFLAGS) $(LIBDIR) -lm -L../lib $(LIBS)
	#$(STRIP) $(TARGET3)

$(TARGET4) : $(OBJS4)
	$(CC) -o $(TARGET4) $(OBJS4) $(CFLAGS) $(CCFLAGS) $(LDFLAGS) $(LIBDIR) -lm -L../lib $(LIBS)
	#$(STRIP) $(TARGET4)

$(TARGET5) : $(OBJS5)
	$(CC) -o $(TARGET5) $(OBJS5) $(CFLAGS) $(CCFLAGS) $(LDFLAGS) $(LIBDIR) -lm -L../lib $(LIBS)
	#$(STRIP) $(TARGET5)

$(TARGET6) : $(OBJS6)
	$(CC) -o $(TARGET6) $(OBJS6) $(CFLAGS) $(CCFLAGS) $(LDFLAGS) $(LIBDIR) -lm -L../lib $(LIBS)
	#$(STRIP) $(TARGET6)

$(TARGET7) : $(OBJS7)
	$(CC) -o $(TARGET7) $(OBJS8) $(CFLAGS) $(CCFLAGS) $(LDFLAGS) $(LIBDIR) -lm -L../lib $(LIBS)
	#$(STRIP) $(TARGET7)

$(TARGET8) : $(OBJS8)
	$(CC) -o $(TARGET8) $(OBJS8) $(CFLAGS) $(CCFLAGS) $(LDFLAGS) $(LIBDIR) -lm -L../lib $(LIBS)
	#$(STRIP) $(TARGET8)

$(TARGET9) : $(OBJS9)
	$(CC) -o $(TARGET9) $(OBJS9) $(CFLAGS) $(CCFLAGS) $(LDFLAGS) $(LIBDIR) -lm -L../lib $(LIBS)
	#$(STRIP) $(TARGET9)

$(TARGET10) : $(OBJS10)
	$(CC) -o $(TARGET10) $(OBJS10) $(CFLAGS) $(CCFLAGS) $(LDFLAGS) $(LIBDIR) -lm -L../lib $(LIBS) -lpthread
	#$(STRIP) $(TARGET10)

$(TARGET11) : $(OBJS11)
	$(CC) -o $(TARGET11) $(OBJS11) $(CFLAGS) $(CCFLAGS) $(LDFLAGS) $(LIBDIR) -lm -L../lib $(LIBS) -lpthread
	#$(STRIP) $(TARGET11)

$(VPK_SCEP) : $(VPK_SCEP_OBJ)
	$(CC) -o $(VPK_SCEP) $(VPK_SCEP_OBJ) $(CFLAGS) $(CCFLAGS) $(LDFLAGS) $(LIBDIR) -lm -L../lib $(LIBS)

clean:
	@rm -f $(TARGET8)
	@rm -f $(TARGET9)
	@rm -f $(TARGET6)
	@rm -f $(TARGET5)
	@rm -f $(TARGET2)
	@rm -f $(TARGET1)
	@rm -f $(TARGET3)
	@rm -f $(TARGET4)
	@rm -rf $(TARGET10)
	@rm -rf $(TARGET11)
	@rm -rf $(VPK_SCEP)
	@rm -f *.o
