include ../buildenv.mk

TARGET = service_provider

RM = rm -f

ifneq ($(SGX_MODE), HW)
	Urts_Library_Name := sgx_urts_sim
else
	Urts_Library_Name := sgx_urts
endif
######## Service Provider Settings ########

DCAP_Verify_Library_Name := sgx_dcap_quoteverify

ServiceProvider_Cpp_Files := service_provider.cpp ecp.cpp udcap_dh.cpp
ServiceProvider_Include_Paths := -I$(SGX_SDK)/include -I$(TOPDIR)/sample_libcrypto -I../Include

ServiceProvider_C_Flags := -fPIC -Wno-attributes $(ServiceProvider_Include_Paths)
ServiceProvider_Cpp_Flags := $(ServiceProvider_C_Flags)
ServiceProvider_Link_Flags := -L$(SGX_SDK)/lib64 -l$(DCAP_Verify_Library_Name) -l$(Urts_Library_Name) -lpthread -ldl -lsample_libcrypto -L$(TOPDIR)/sample_libcrypto -Wl,-rpath=$(TOPDIR)/sample_libcrypto 

ServiceProvider_Cpp_Objects := $(ServiceProvider_Cpp_Files:.cpp=.o) 

######## Service Provider Objects ########
.PHONY = all clean

all: $(TARGET)

%.o: %.cpp
	@$(CXX) $(ServiceProvider_Cpp_Flags) -c $< -o $@
	@echo "CXX  <=  $<"

fifo.o: fifo.cpp
	@$(CXX) $(ServiceProvider_Cpp_Flags) -c $< -o $@
	@echo "CXX   <=  $<"

$(TARGET): $(ServiceProvider_Cpp_Objects) fifo.o
	@$(CXX) $^ -o $@ $(ServiceProvider_Link_Flags)
	@echo "LINK =>  $@"
	@mv $@ $(TOPDIR)/$(OUTDIR)/

clean:
	@$(RM) $(TARGET) service_provider $(ServiceProvider_Cpp_Objects) 
