LK_SRC_DIR := /lib/modules/$(shell uname -r)/build

.PHONY: all clean

all:
	$(MAKE) -C $(LK_SRC_DIR) M=$(PWD) modules
	
clean:
	$(MAKE) -C $(LK_SRC_DIR) M=$(PWD) clean

