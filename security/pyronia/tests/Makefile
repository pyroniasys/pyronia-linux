IDIR=../include
LDIR=..
CC=gcc
CFLAGS=-iquote$(IDIR) -I../../../include -DPYR_TESTING=0
MAKEFLAGS += --silent

TESTS = lib_policy_creation_test callgraph_creation_test \
        policy_verification_test

all: $(TESTS)

_DEPS = userland_test.h lib_policy.h callgraph.h
DEPS = $(patsubst %,$(IDIR)/%,$(_DEPS))

_LIB = lib_policy.o callgraph.o
LIB = $(patsubst %,$(LDIR)/%,$(_LIB))

callgraph_creation_test: $(LIB) callgraph_creation.c ; $(CC) $^ -o $@
lib_policy_creation_test: $(LIB) lib_policy_creation.c ; $(CC) $^ -o $@
policy_verification_test: $(LIB) policy_verification.c ; $(CC) $^ -o $@

$(LDIR)/%.o: %.c $(DEPS) ; $(CC) -c -o $@ $< $(CFLAGS)

.PHONY: clean test

test: ; for t in $(TESTS); do bash test.sh $$t ; done

clean: ; rm -rf *.o $(LDIR)/*.o *~ *_test $(IDIR)/*~
