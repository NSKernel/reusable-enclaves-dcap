#
# Copyright (C) 2011-2021 Intel Corporation. All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
#   * Redistributions of source code must retain the above copyright
#     notice, this list of conditions and the following disclaimer.
#   * Redistributions in binary form must reproduce the above copyright
#     notice, this list of conditions and the following disclaimer in
#     the documentation and/or other materials provided with the
#     distribution.
#   * Neither the name of Intel Corporation nor the names of its
#     contributors may be used to endorse or promote products derived
#     from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
#

include buildenv.mk

ifeq ($(SGX_MODE), HW)
ifeq ($(SGX_DEBUG), 1)
		Build_Mode = HW_DEBUG
else ifeq ($(SGX_PRERELEASE), 1)
		Build_Mode = HW_PRERELEASE
else
		Build_Mode = HW_RELEASE
endif
endif

SUB_DIR := service_provider GatewayApp GatewayEnclave

ifneq ($(OUTDIR),)
$(shell mkdir -p $(OUTDIR))
endif

.PHONY: all clean

all:
	for dir in $(SUB_DIR); do \
		$(MAKE) -C $$dir; \
	done
ifeq ($(Build_Mode), HW_DEBUG)
	@echo "The project has been built in hardware debug mode."
else ifeq ($(Build_Mode), HW_RELEAESE)
	@echo "The project has been built in hardware release mode."
else ifeq ($(Build_Mode), HW_PRERELEAESE)
	@echo "The project has been built in hardware pre-release mode."
endif

# .config_$(Build_Mode)_$(SGX_ARCH):
# 	@rm -f .config_* $(OUTDIR)/gatewayapp $(OUTDIR)/gatewayapp $(OUTDIR)/libgateway_enclave.so $(OUTDIR)/libgateway_enclave.signed.so GatewayApp/*.o GatewayApp/GatewayEnclave_u.* GatewayEnclave/*.o GatewayEnclave/GatewayEnclave_t.* $(OUTDIR)/libservice_provider.* service_provider/*.o
# 	@touch .config_$(Build_Mode)_$(SGX_ARCH)

clean:
	@rm -rf $(OUTDIR)
	for dir in $(SUB_DIR); do \
		$(MAKE) -C $$dir clean; \
	done
	rm -f .config_* util/*.o
	
