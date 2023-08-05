/*
 * Copyright (C) 2011-2021 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */



#include "service_provider.h"

#include "sample_libcrypto.h"

#include "udcap_dh.h"

#include <stdlib.h>
#include "error_codes.h"
#include "fifo_def.h"
#include "dcap_dh_def.h"
#include "datatypes.h"
#include <map>

using namespace std;

#define FILE_SIZE 1452
uint8_t g_secret[] = {0x4f, 0x85, 0xd3, 0x93, 0xc, 0x44, 0x9c, 0xdd,
    0x3e, 0x81, 0xbd, 0xb6, 0xa2, 0x44, 0x16, 0x5f,
    0xa8, 0x56, 0x72, 0xc1, 0x14, 0x41, 0xa, 0x2f,
    0xdc, 0xb0, 0xa8, 0xa1, 0x3a, 0x51, 0x40, 0xf9,
    0x12, 0x9f, 0x11, 0x86, 0xe9, 0x1a, 0xf1, 0x16,
    0xbc, 0xd4, 0x6, 0x2f, 0x47, 0x2c, 0xc3, 0x37,
    0x8e, 0x65, 0x7, 0x29, 0x85, 0xb0, 0x8, 0x61,
    0x6b, 0x6d, 0xc7, 0x22, 0x7d, 0x22, 0x61, 0x7f,
    0x40, 0x43, 0x40, 0x5a, 0x7a, 0xf4, 0x94, 0x0,
    0x60, 0x36, 0xf6, 0xa4, 0x22, 0x22, 0x41, 0x82,
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    0x2, 0x0, 0x1, 0x0, 0x3, 0x1, 0x0, 0x0,
    0x1, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0,
    0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x20,
    0x58, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    0x2, 0x2, 0xff, 0xff, 0xff, 0x1, 0x0, 0x0,
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    0x7, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    0x7, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    0xe2, 0x55, 0x5d, 0xc6, 0xe6, 0x69, 0x53, 0xc0,
    0x8d, 0x52, 0x5b, 0xc0, 0x2a, 0x2c, 0x5c, 0x2f,
    0xc, 0x8c, 0xfe, 0x5b, 0x1, 0xae, 0x89, 0xff,
    0x2, 0x2f, 0x97, 0xea, 0x9b, 0x45, 0xb6, 0x2e,
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    0x60, 0x27, 0x7a, 0xd2, 0xfd, 0xfc, 0x57, 0xe9,
    0x80, 0xe8, 0x76, 0xe7, 0xf8, 0x78, 0xac, 0x19,
    0x9, 0x88, 0xe, 0xa5, 0x38, 0x7, 0x95, 0xa7,
    0xe8, 0xea, 0x98, 0xb1, 0x57, 0x84, 0x1f, 0x85,
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    0xdd, 0xda, 0x3e, 0x6b, 0x72, 0xa2, 0xd7, 0x31,
    0x31, 0x32, 0xbd, 0xf3, 0xf4, 0xc0, 0xe3, 0xaa,
    0x16, 0x19, 0x72, 0x47, 0x92, 0xe7, 0x8f, 0xf8,
    0x40, 0x2b, 0xa7, 0xc0, 0xb9, 0x77, 0xb1, 0x1c,
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    0xa8, 0x2, 0x0, 0x0, 0x2e, 0x23, 0x7d, 0xe8,
    0x5d, 0xcd, 0x6d, 0x88, 0x6f, 0xad, 0xd3, 0x4c,
    0x7e, 0xed, 0xff, 0xa2, 0xea, 0x1c, 0xd5, 0xc8,
    0x54, 0xbb, 0x93, 0xc8, 0x1b, 0xbe, 0xbe, 0x51,
    0x6b, 0x8d, 0xb7, 0x90, 0x7f, 0x87, 0x9f, 0x9b,
    0x66, 0x4f, 0xeb, 0xf4, 0x34, 0xbb, 0x90, 0x5d,
    0xc5, 0x20, 0x7b, 0xd2, 0x5a, 0x92, 0x42, 0x80,
    0x2f, 0x3f, 0xc2, 0x64, 0x7e, 0x77, 0xa, 0x49,
    0xdb, 0xde, 0x77, 0x88, 0xd7, 0xce, 0xdb, 0x2e,
    0x44, 0x50, 0x26, 0xd8, 0x7a, 0xe, 0x1c, 0x7f,
    0x63, 0x36, 0x62, 0xa8, 0xa7, 0x2e, 0x60, 0x56,
    0xf4, 0xbc, 0xb5, 0xca, 0xc3, 0x81, 0x9e, 0x84,
    0xb8, 0xc, 0xef, 0x7a, 0x18, 0x4a, 0x5b, 0x3,
    0x0, 0xe3, 0x8c, 0x3f, 0x2e, 0xf9, 0x9a, 0xf7,
    0x72, 0xe1, 0xa0, 0x5e, 0x6a, 0x4c, 0x68, 0xea,
    0x67, 0xfc, 0xe8, 0x21, 0x27, 0x90, 0xae, 0xbf,
    0x51, 0xa4, 0xc9, 0xae, 0x3d, 0x3b, 0x5c, 0x53,
    0x7e, 0x25, 0xa4, 0x6f, 0x78, 0x99, 0x35, 0x2e,
    0x48, 0x50, 0xf9, 0xf0, 0x63, 0x90, 0x19, 0x6a,
    0xc, 0x3d, 0x48, 0x2a, 0x5f, 0x6f, 0xb, 0xd7,
    0x26, 0x64, 0xb5, 0xe0, 0x60, 0x36, 0x69, 0x40,
    0x9c, 0x21, 0x29, 0xe0, 0xca, 0xae, 0xd1, 0x7a,
    0x4, 0xb8, 0x8d, 0x96, 0x74, 0xa3, 0x7, 0xa4,
    0x41, 0x9e, 0xf7, 0x9, 0xbe, 0x8f, 0xe8, 0x65,
    0xd9, 0x26, 0x16, 0xa1, 0xef, 0x1b, 0xf4, 0xb7,
    0xd5, 0xfe, 0xd6, 0x7d, 0xa6, 0x6c, 0x50, 0x8c,
    0x90, 0x34, 0x1f, 0x17, 0x8c, 0x14, 0x38, 0x6d,
    0xd7, 0x83, 0x1a, 0x1e, 0xcf, 0xf5, 0xb, 0xdb,
    0x26, 0x8f, 0x23, 0xf9, 0x4f, 0x41, 0x73, 0xac,
    0x9d, 0xfa, 0x77, 0x3, 0x6a, 0x32, 0xbb, 0x37,
    0x93, 0x47, 0x38, 0x93, 0x39, 0xd2, 0x51, 0x46,
    0xaf, 0xfd, 0x71, 0xda, 0x89, 0xc7, 0x44, 0xb0,
    0xf3, 0x95, 0x74, 0x3b, 0xbc, 0x7d, 0x86, 0xc1,
    0x6e, 0x49, 0xd8, 0x52, 0xc, 0xc1, 0x88, 0x72,
    0x5, 0x5c, 0x92, 0x12, 0x22, 0x95, 0xc5, 0x12,
    0xf5, 0xfa, 0x11, 0x8d, 0x50, 0x42, 0x33, 0x4,
    0x41, 0x17, 0x90, 0xc8, 0xb3, 0x1d, 0x2e, 0xe5,
    0x13, 0xf5, 0xd6, 0xb1, 0xc5, 0xd4, 0x6d, 0xe1,
    0x68, 0x1, 0x0, 0x0, 0xc4, 0x15, 0xbf, 0x91,
    0xf1, 0xad, 0xb1, 0x9f, 0x9b, 0x6b, 0x8d, 0xa2,
    0xdf, 0x7d, 0x6, 0xf8, 0xba, 0x73, 0xb7, 0xb,
    0x72, 0xcc, 0x34, 0x4d, 0x52, 0x3b, 0x76, 0xfd,
    0x8e, 0x3a, 0x67, 0xcc, 0x36, 0xb, 0xa9, 0xc2,
    0x90, 0x37, 0x77, 0x75, 0x90, 0xb8, 0x97, 0x44,
    0xed, 0xb4, 0x61, 0xe8, 0x11, 0xe9, 0x2, 0x50,
    0xde, 0x98, 0x99, 0x3e, 0xf6, 0x5c, 0x71, 0x92,
    0x49, 0xcb, 0x0, 0x72, 0xe0, 0x55, 0xa9, 0x6e,
    0xc7, 0x2, 0xf4, 0x2b, 0x3c, 0xe3, 0x42, 0x7e,
    0x8b, 0xf, 0x26, 0xd9, 0x42, 0x21, 0xd5, 0x74,
    0xe3, 0x35, 0xb3, 0xb8, 0xfe, 0x25, 0x1d, 0x47,
    0x5b, 0x35, 0x8d, 0xfd, 0x18, 0x77, 0x29, 0xd9,
    0x69, 0x2b, 0x67, 0x54, 0x8c, 0xf5, 0xd7, 0x84,
    0x36, 0xf3, 0x96, 0xca, 0xb9, 0x42, 0xad, 0xd6,
    0xba, 0x8d, 0x2f, 0xfc, 0x21, 0xfe, 0xa7, 0xea,
    0x59, 0x94, 0xfe, 0x95, 0x1f, 0x1e, 0xb9, 0xca,
    0x5e, 0x4d, 0xf1, 0x2, 0x68, 0x91, 0xf7, 0xa1,
    0xea, 0x11, 0x90, 0x95, 0x1c, 0xf7, 0x85, 0xd4,
    0x70, 0xf9, 0x49, 0xae, 0x5e, 0xa5, 0x62, 0x3d,
    0x35, 0xc5, 0xdf, 0xc1, 0x7f, 0xc7, 0x39, 0x5a,
    0x3b, 0x89, 0x8c, 0x80, 0x71, 0xe7, 0xbc, 0xbf,
    0x4e, 0x72, 0x6d, 0xd7, 0xe0, 0xa2, 0xb0, 0x7d,
    0xca, 0x89, 0x22, 0x6, 0xb2, 0xb4, 0x3c, 0xa2,
    0xed, 0x51, 0xf, 0xa2, 0xf7, 0xc9, 0x89, 0xf0,
    0x27, 0x2f, 0xf6, 0x41, 0x4e, 0xa, 0x2b, 0x67,
    0x49, 0x44, 0x8e, 0x40, 0xc6, 0xb8, 0xad, 0xb8,
    0x40, 0xb, 0xba, 0x73, 0x2e, 0x1d, 0x4, 0xc9,
    0x28, 0x62, 0x6b, 0x3d, 0xe6, 0x5f, 0x1c, 0xdd,
    0xae, 0x27, 0x6d, 0x3c, 0x2d, 0xf6, 0x42, 0x3b,
    0x91, 0x1, 0x37, 0x47, 0x76, 0x5, 0xbc, 0x7,
    0x8c, 0x6, 0x81, 0x77, 0x70, 0x9d, 0x8a, 0x75,
    0x34, 0x1, 0x68, 0x1a, 0x38, 0x13, 0x11, 0x74,
    0xf2, 0x70, 0x4f, 0x9b, 0x86, 0x15, 0xc6, 0xbc,
    0x6b, 0x1a, 0x56, 0x3f, 0x4f, 0xfa, 0xd4, 0x17,
    0x97, 0xbb, 0x4b, 0x91, 0x3b, 0x54, 0xf7, 0x8e,
    0x53, 0xf5, 0x2, 0x21, 0x3b, 0x66, 0xf9, 0xe5,
    0x79, 0xff, 0xeb, 0x5c, 0x66, 0x1b, 0x34, 0xf4,
    0x41, 0xd1, 0x9a, 0xdb, 0x1f, 0x3e, 0xe3, 0x8a,
    0x90, 0x98, 0x9e, 0x73, 0xb9, 0xa8, 0x20, 0xfe,
    0xe7, 0xe3, 0x9f, 0x83, 0xd3, 0x95, 0x5f, 0xa,
    0x40, 0x53, 0x6a, 0xd3, 0x72, 0x32, 0xde, 0xf1,
    0xf, 0x98, 0x2b, 0x7d, 0x6e, 0x76, 0xbd, 0x31,
    0x84, 0x99, 0x1c, 0xdc, 0xac, 0x78, 0x44, 0xbf,
    0x29, 0xdd, 0x2e, 0xe3, 0x39, 0x9d, 0x38, 0x83,
    0xa, 0x3e, 0x83, 0xb6, 0x74, 0x44, 0x4d, 0x78,
    0x55, 0xb2, 0xe0, 0x74, 0x25, 0x61, 0x67, 0xc0,
    0xe8, 0x1e, 0x5e, 0xd8};

size_t max_out_buff_size = 2048;
size_t buffer_size = FILE_SIZE;
// this is expected gateway's MRSIGNER for demonstration purpose
sgx_measurement_t g_gateway_mrsigner = {
        {
                0xc3, 0x04, 0x46, 0xb4, 0xbe, 0x9b, 0xaf, 0x0f, 0x69, 0x72, 0x84, 0x23, 0xea, 0x61, 0x3e, 0xf8,
                0x1a, 0x63, 0xe7, 0x2a, 0xcf, 0x74, 0x39, 0xfa, 0x05, 0x49, 0x00, 0x1f, 0xd5, 0x48, 0x28, 0x35
        }
};

/* Function Description: This is interface for service provider to get ECDH message 1 and session id from gateway enclave
 * Parameter Description:
 *      dh_msg1: pointer to ecdh msg1 buffer, this buffer is allocated in service provider and filled by gateway enclave
 *      session_id: pointer to session id which is allocated by gateway enclave
 * */
ATTESTATION_STATUS session_request(sgx_dh_dcap_msg1_t* dh_msg1, uint32_t* session_id, sgx_enclave_id_t gateway_enclave_id)
{
	FIFO_MSG msg1_request;
	FIFO_MSG *msg1_response;
	SESSION_MSG1_RESP * msg1_respbody = NULL;
	size_t  msg1_resp_size;

	msg1_request.header.type = FIFO_DH_REQ_MSG1;
	msg1_request.header.size = 0;

	if ((client_send_receive(&msg1_request, sizeof(FIFO_MSG), &msg1_response, &msg1_resp_size, gateway_enclave_id) != 0)
		|| (msg1_response == NULL))
	{
		printf("fail to send and receive message.\n");
		return INVALID_SESSION;
	}

	msg1_respbody = (SESSION_MSG1_RESP *)msg1_response->msgbuf;
	memcpy(dh_msg1, &msg1_respbody->dh_msg1, sizeof(sgx_dh_dcap_msg1_t));
	*session_id = msg1_respbody->sessionid;
        free(msg1_response);

	return (ATTESTATION_STATUS)0;

}

/* Function Description: This is interface for service provider to send ECDH message 2 to gateway enclave, and receive ECDH message 3 from gateway enclave
 * Parameter Description:
 *      dh_msg2: this is pointer to ECDH message 2 generated by service provider
 *      dh_msg3: this is pointer to ECDH message 3, this buffer is allocated in service provider and filled by gateway enclave
 *      session_id: this is session id allocated by gateway enclave
 * */
ATTESTATION_STATUS exchange_report(sgx_dh_dcap_msg2_t *dh_msg2, sgx_dh_dcap_msg3_t *dh_msg3, uint32_t session_id, sgx_enclave_id_t gateway_enclave_id)
{
	FIFO_MSG * msg2 = NULL, * msg3 = NULL;
	FIFO_MSG_HEADER * msg2_header = NULL;
	SESSION_MSG2 *msg2_body = NULL;
	SESSION_MSG3 *msg3_body = NULL;
	size_t msg2size, msg3size;

	msg2size = sizeof(FIFO_MSG_HEADER) + sizeof(SESSION_MSG2);
	msg2 = (FIFO_MSG *)malloc(msg2size);
	if (!msg2)
	{
		return ERROR_OUT_OF_MEMORY;
	}
	memset(msg2, 0, msg2size);

	msg2_header = (FIFO_MSG_HEADER *)msg2;
	msg2_header->type = FIFO_DH_MSG2;
	msg2_header->size = sizeof(SESSION_MSG2);

	msg2_body = (SESSION_MSG2 *)msg2->msgbuf;
	memcpy(&msg2_body->dh_msg2, dh_msg2, sizeof(sgx_dh_dcap_msg2_t));
	msg2_body->sessionid = session_id;

	if (client_send_receive(msg2, msg2size, &msg3, &msg3size, gateway_enclave_id) != 0)
	{
		free(msg2);
		printf("failed to send and receive message.\n");
		return INVALID_SESSION;
	}

	msg3_body = (SESSION_MSG3 *)msg3->msgbuf;
	memcpy(dh_msg3, &msg3_body->dh_msg3, sizeof(sgx_dh_dcap_msg3_t));

	free(msg3);
	free(msg2);

	return (ATTESTATION_STATUS)0;
}

/* Function Description:
 *   this is to verify peer enclave's identity
 * For demonstration purpose, we verify below points:
 *   1. peer enclave's MRSIGNER is as expected
 *   2. peer enclave's PROD_ID is as expected
 *   3. peer enclave's attribute is reasonable that it should be INITIALIZED and without DEBUG attribute (except the project is built with DEBUG option)
 * */
uint32_t verify_peer_enclave_trust(sgx_dh_session_enclave_identity_t* peer_enclave_identity)
{
    if(!peer_enclave_identity)
        return INVALID_PARAMETER_ERROR;

    // check peer enclave's MRSIGNER
    if (memcmp((uint8_t *)&peer_enclave_identity->mr_signer, (uint8_t*)&g_gateway_mrsigner, sizeof(sgx_measurement_t)))
        return ENCLAVE_TRUST_ERROR;

    if(peer_enclave_identity->isv_prod_id != 0 || !(peer_enclave_identity->attributes.flags & SGX_FLAGS_INITTED))
        return ENCLAVE_TRUST_ERROR;

    return SUCCESS;
}

//Create a session with the destination enclave
ATTESTATION_STATUS create_session(dh_session_t *session_info, sgx_enclave_id_t gateway_enclave_id)
{
    sgx_dh_dcap_msg1_t dh_msg1;            //Diffie-Hellman Message 1
    sgx_key_128bit_t dh_aek;        // Session Key
    sgx_dh_dcap_msg2_t dh_msg2;            //Diffie-Hellman Message 2
    sgx_dh_dcap_msg3_t dh_msg3;            //Diffie-Hellman Message 3
    uint32_t session_id;
    uint32_t retstatus;
    sample_status_t status = SAMPLE_SUCCESS;
    sgx_dh_session_t sgx_dh_session;
    sgx_dh_session_enclave_identity_t responder_identity;

    if(!session_info)
    {
        return INVALID_PARAMETER_ERROR;
    }

    memset(&dh_aek,0, sizeof(sgx_key_128bit_t));
    memset(&dh_msg1, 0, sizeof(sgx_dh_dcap_msg1_t));
    memset(&dh_msg2, 0, sizeof(sgx_dh_dcap_msg2_t));
    memset(&dh_msg3, 0, sizeof(sgx_dh_dcap_msg3_t));
    memset(session_info, 0, sizeof(dh_session_t));

    //Intialize the session as a session initiator
	printf("Intialize the session as a session initiator\n");
    status = sgx_dh_dcap_init_session(SGX_DH_SESSION_INITIATOR, &sgx_dh_session);
    if(SAMPLE_SUCCESS != status)
    {
            return status;
    }
	printf("Intialize the session as a session initiator success\n");

    //Request for a session with the gateway enclave and obtain session id and Message 1 if successful
	printf("Request for a session with the gateway enclave and obtain session id and Message 1\n");
    retstatus = session_request(&dh_msg1, &session_id, gateway_enclave_id);
    if ((ATTESTATION_STATUS)retstatus != SUCCESS){
        return ((ATTESTATION_STATUS)retstatus);
    }
	printf("Request for a session with the gateway enclave and obtain session id and Message 1 success\n");

    //Process the message 1 obtained from desination enclave and generate message 2
	printf("Process the message 1 obtained from desination enclave and generate message 2\n");
    status = sgx_dh_dcap_initiator_proc_msg1(&dh_msg1, &dh_msg2, &sgx_dh_session);
    if(SAMPLE_SUCCESS != status)
    {
         return status;
    }
	printf("Process the message 1 obtained from desination enclave and generate message 2\n");

    //Send Message 2 to Destination Enclave and get Message 3 in return
	printf("Send Message 2 to Destination Enclave and get Message 3 in return\n");
    retstatus = exchange_report(&dh_msg2, &dh_msg3, session_id, gateway_enclave_id);
    if ((ATTESTATION_STATUS)retstatus != SUCCESS){
        return ((ATTESTATION_STATUS)retstatus);
    }
	printf("Send Message 2 to Destination Enclave and get Message 3 in return success\n");

    //Process Message 3 obtained from the destination enclave
	printf("Process Message 3 obtained from the destination enclave\n");
    status = sgx_dh_dcap_initiator_proc_msg3(&dh_msg3, &sgx_dh_session, &dh_aek, &responder_identity);
    if(SAMPLE_SUCCESS != status)
    {
        return status;
    }
	printf("Process Message 3 obtained from the destination enclave success\n");

    // Verify the identity of the destination enclave
	printf("Verify the identity of the destination enclave\n");
    if(verify_peer_enclave_trust(&responder_identity) != SUCCESS)
    {
        return INVALID_SESSION;
    }
	printf("Verify the identity of the destination enclave success\n");

    memcpy(session_info->active.AEK, &dh_aek, sizeof(sgx_key_128bit_t));
    session_info->session_id = session_id;
    session_info->active.counter = 0;
    session_info->status = ACTIVE;
    memset(&dh_aek,0, sizeof(sgx_key_128bit_t));
    return status;
}

/* Function Description: This is interface for gateway enclave to send request message(encrypted) to wasm vm enclave, and receive response message from wasm vm enclave
 * Parameter Description:
 *      [input] session_id: this is session id allocated by wasm vm enclave
 *      [input] req_message: this is pointer to request message
 *      [input] req_message_size: this is request message size
 *      [input] max_payload_size: this is maximum payload size in response message
 *      [input, output] this is pointer to response message, the buffer is allocated by gateway enclave and filled by wasm vm enclave
 *      [input] response message size
 * */
ATTESTATION_STATUS send_request(uint32_t session_id, secure_message_t* req_message, size_t req_message_size, size_t max_payload_size, secure_message_t* resp_message, size_t resp_message_size, sgx_enclave_id_t gateway_enclave_id)
{
	FIFO_MSG *msgreq = NULL, * msgresp= NULL;
	FIFO_MSGBODY_REQ * msgbody;

	size_t reqsize, respsize;

	reqsize = sizeof(FIFO_MSG_HEADER) + sizeof(FIFO_MSGBODY_REQ) + req_message_size;

	msgreq = (FIFO_MSG *)malloc(reqsize);
	if (!msgreq)
	{
		return ERROR_OUT_OF_MEMORY;
	}
	memset(msgreq, 0, reqsize);

	msgreq->header.type = FIFO_DH_MSG_REQ;
	msgreq->header.size = sizeof(FIFO_MSGBODY_REQ) + req_message_size;

	msgbody = (FIFO_MSGBODY_REQ *)msgreq->msgbuf;
	msgbody->max_payload_size = max_payload_size;
	msgbody->size = req_message_size;
	msgbody->session_id = session_id;

	memcpy(msgbody->buf, req_message, req_message_size);

	if (client_send_receive(msgreq, reqsize, &msgresp, &respsize, gateway_enclave_id) != 0)
	{
		free(msgreq);
		printf("fail to send and receive message.\n");
		return INVALID_SESSION;
	}

	//TODO copy to output message pointer
	memcpy(resp_message, msgresp->msgbuf, msgresp->header.size < resp_message_size ? msgresp->header.size : resp_message_size);

	free(msgresp);
	free(msgreq);

	return (ATTESTATION_STATUS)0;
}

//Request for the response size, send the request message to the destination enclave and receive the response message back
ATTESTATION_STATUS send_request_receive_response(dh_session_t *session_info,
                                  uint8_t *inp_buff,
                                  size_t inp_buff_len,
                                  size_t max_out_buff_size,
                                  uint8_t *out_buff,
                                  size_t* out_buff_len,
                                  sgx_enclave_id_t gateway_enclave_id)
{
    const uint8_t* plaintext;
    uint32_t plaintext_length;
    sample_status_t status;
    uint32_t retstatus;
    secure_message_t* req_message;
    secure_message_t* resp_message;
    uint8_t *decrypted_data;
    uint32_t decrypted_data_length;
    uint32_t plain_text_offset;
    uint8_t l_tag[TAG_SIZE];
    size_t max_resp_message_length;
    plaintext = (const uint8_t*)(" ");
    plaintext_length = 0;

    if(!session_info || !inp_buff)
    {
        return INVALID_PARAMETER_ERROR;
    }
    //Check if the nonce for the session has not exceeded 2^32-2 if so end session and start a new session
    if(session_info->active.counter == ((uint32_t) - 2))
    {
        close_session(session_info, gateway_enclave_id);
        create_session(session_info, gateway_enclave_id);
    }
    
    //Allocate memory for the AES-GCM request message
    req_message = (secure_message_t*)malloc(sizeof(secure_message_t)+ inp_buff_len);
    if(!req_message)
        return MALLOC_ERROR;
    memset(req_message, 0, sizeof(secure_message_t)+ inp_buff_len);

    const uint32_t data2encrypt_length = (uint32_t)inp_buff_len;

    //Set the payload size to data to encrypt length
    req_message->message_aes_gcm_data.payload_size = data2encrypt_length;

    //Use the session nonce as the payload IV
    memcpy(req_message->message_aes_gcm_data.reserved, &session_info->active.counter, sizeof(session_info->active.counter));

    //Set the session ID of the message to the current session id
    req_message->session_id = session_info->session_id;

    //Prepare the request message with the encrypted payload
    status = sample_rijndael128GCM_encrypt(&session_info->active.AEK, (uint8_t*)inp_buff, data2encrypt_length,
                reinterpret_cast<uint8_t *>(&(req_message->message_aes_gcm_data.payload)),
                reinterpret_cast<uint8_t *>(&(req_message->message_aes_gcm_data.reserved)),
                sizeof(req_message->message_aes_gcm_data.reserved), plaintext, plaintext_length,
                &(req_message->message_aes_gcm_data.payload_tag));

    if(SGX_SUCCESS != status)
    {
        SAFE_FREE(req_message);
        return status;
    }

    //Allocate memory for the response message
    resp_message = (secure_message_t*)malloc(sizeof(secure_message_t)+ max_out_buff_size);
    if(!resp_message)
    {
        SAFE_FREE(req_message);
        return MALLOC_ERROR;
    }

    memset(resp_message, 0, sizeof(secure_message_t)+ max_out_buff_size);

    //Ocall to send the request to the Destination Enclave and get the response message back
    retstatus = send_request(session_info->session_id, req_message,
                                (sizeof(secure_message_t)+ inp_buff_len), max_out_buff_size,
                                resp_message, (sizeof(secure_message_t)+ max_out_buff_size), gateway_enclave_id);
    if ((ATTESTATION_STATUS)retstatus != SUCCESS)
    {
        SAFE_FREE(req_message);
        SAFE_FREE(resp_message);
        return ((ATTESTATION_STATUS)retstatus);
    }

    max_resp_message_length = sizeof(secure_message_t)+ max_out_buff_size;

    if(sizeof(resp_message) > max_resp_message_length)
    {
        SAFE_FREE(req_message);
        SAFE_FREE(resp_message);
        return INVALID_PARAMETER_ERROR;
    }

    //Code to process the response message from the Destination Enclave

    decrypted_data_length = resp_message->message_aes_gcm_data.payload_size;
    plain_text_offset = decrypted_data_length;
    decrypted_data = (uint8_t*)malloc(decrypted_data_length);
    if(!decrypted_data)
    {
        SAFE_FREE(req_message);
        SAFE_FREE(resp_message);
        return MALLOC_ERROR;
    }
    memset(&l_tag, 0, 16);

    memset(decrypted_data, 0, decrypted_data_length);

    //Decrypt the response message payload
    status = sample_rijndael128GCM_decrypt(&session_info->active.AEK, resp_message->message_aes_gcm_data.payload,
                decrypted_data_length, decrypted_data,
                reinterpret_cast<uint8_t *>(&(resp_message->message_aes_gcm_data.reserved)),
                sizeof(resp_message->message_aes_gcm_data.reserved), &(resp_message->message_aes_gcm_data.payload[plain_text_offset]), plaintext_length,
                &resp_message->message_aes_gcm_data.payload_tag);
    
    if(SGX_SUCCESS != status)
    {
        SAFE_FREE(req_message);
        SAFE_FREE(decrypted_data);
        SAFE_FREE(resp_message);
        printf("Service Provider: Failed to decrypt response\n");
        return status;
    }

    // Verify if the nonce obtained in the response is equal to the session nonce + 1 (Prevents replay attacks)
    if(*((uint32_t*)resp_message->message_aes_gcm_data.reserved) != (session_info->active.counter + 1 ))
    {
        SAFE_FREE(req_message);
        SAFE_FREE(resp_message);
        SAFE_FREE(decrypted_data);
        printf("Service Provider: Response with incorrect nonce\n");
        return INVALID_PARAMETER_ERROR;
    }

        //Update the value of the session nonce in the source enclave
    session_info->active.counter = session_info->active.counter + 1;

    *out_buff_len = decrypted_data_length;
    // memcpy(out_buff_len, &decrypted_data_length, sizeof(decrypted_data_length));
    memcpy(out_buff, decrypted_data, decrypted_data_length);

    SAFE_FREE(decrypted_data);
    SAFE_FREE(req_message);
    SAFE_FREE(resp_message);
    return SUCCESS;
}

ATTESTATION_STATUS encrypt_payload(dh_session_t *session_info,
                                  uint8_t *inp_buff,
                                  size_t inp_buff_len,
                                  uint8_t **out_buff,
                                  size_t* out_buff_len,
                                  sgx_enclave_id_t gateway_enclave_id)
{
    const uint8_t* plaintext;
    uint32_t plaintext_length;
    sample_status_t status;
    secure_message_t* req_message;
    size_t max_resp_message_length;
    plaintext = (const uint8_t*)(" ");
    plaintext_length = 0;

    if(!session_info || !inp_buff)
    {
        return INVALID_PARAMETER_ERROR;
    }
    
    //Allocate memory for the AES-GCM request message
    req_message = (secure_message_t*)malloc(sizeof(secure_message_t)+ inp_buff_len);
    if(!req_message)
        return MALLOC_ERROR;
    memset(req_message, 0, sizeof(secure_message_t)+ inp_buff_len);

    const uint32_t data2encrypt_length = (uint32_t)inp_buff_len;

    //Set the payload size to data to encrypt length
    req_message->message_aes_gcm_data.payload_size = data2encrypt_length;

    //Use the session nonce as the payload IV
    memcpy(req_message->message_aes_gcm_data.reserved, &session_info->active.counter, sizeof(session_info->active.counter));

    //Set the session ID of the message to the current session id
    req_message->session_id = session_info->session_id;

    //Prepare the request message with the encrypted payload
    status = sample_rijndael128GCM_encrypt(&session_info->active.AEK, (uint8_t*)inp_buff, data2encrypt_length,
                reinterpret_cast<uint8_t *>(&(req_message->message_aes_gcm_data.payload)),
                reinterpret_cast<uint8_t *>(&(req_message->message_aes_gcm_data.reserved)),
                sizeof(req_message->message_aes_gcm_data.reserved), plaintext, plaintext_length,
                &(req_message->message_aes_gcm_data.payload_tag));

    if(SGX_SUCCESS != status)
    {
        SAFE_FREE(req_message);
        return status;
    }

    *out_buff_len = sizeof(secure_message_t)+ inp_buff_len;
    *out_buff = (uint8_t *)req_message;
    return SUCCESS;
}

/* Function Description: this is interface for gateway enclave to close secure session
 * Parameter Description:
 *      [input] session_id: this is session id allocated by wasm vm enclave
 * */
ATTESTATION_STATUS end_session(uint32_t session_id, sgx_enclave_id_t gateway_enclave_id)
{
	FIFO_MSG *msgresp = NULL;
	FIFO_MSG *closemsg;
	SESSION_CLOSE_REQ * body;
	size_t reqsize, respsize;

	reqsize = sizeof(FIFO_MSG) + sizeof(SESSION_CLOSE_REQ);
	closemsg = (FIFO_MSG *)malloc(reqsize);
	if (!closemsg)
	{
		return ERROR_OUT_OF_MEMORY;
	}
	memset(closemsg, 0,reqsize);

	closemsg->header.type = FIFO_DH_CLOSE_REQ;
	closemsg->header.size = sizeof(SESSION_CLOSE_REQ);

	body = (SESSION_CLOSE_REQ *)closemsg->msgbuf;
	body->session_id = session_id;

	if (client_send_receive(closemsg, reqsize, &msgresp, &respsize, gateway_enclave_id) != 0)
	{
		free(closemsg);
		printf("fail to send and receive message.\n");
		return INVALID_SESSION;
	}

	free(closemsg);
	free(msgresp);

	return (ATTESTATION_STATUS)0;
}

//Close a current session
ATTESTATION_STATUS close_session(dh_session_t *session_info, sgx_enclave_id_t gateway_enclave_id)
{
    uint32_t retstatus;

    if(!session_info)
    {
        return INVALID_PARAMETER_ERROR;
    }

    //Ocall to ask the destination enclave to end the session
    retstatus = end_session( session_info->session_id, gateway_enclave_id);
 
    if ((ATTESTATION_STATUS)retstatus != SUCCESS){
        return ((ATTESTATION_STATUS)retstatus);
    }
    return SUCCESS;
}

#include "../Include/wasm_request.h"
#include <errno.h>
#include <cstdio>

static uint8_t *
read_file_to_request(const char *filename, uint64_t *size)
{
    uint8_t *buffer;
    FILE *file;
    uint64_t file_size, read_size;

    if (!filename || !size) {
        printf("Read file to buffer failed: invalid filename or ret size.\n");
        return NULL;
    }

    file = fopen(filename, "r");
    if (file == NULL) {
        printf("Read file to buffer failed: open file %s failed with error %d.\n",
               filename, errno);
        return NULL;
    }

    fseek(file, 0, SEEK_END);
    file_size = ftell(file);
    fseek(file, 0, SEEK_SET);

    if ((buffer = (uint8_t *)malloc(file_size)) == NULL) {
        printf("Read file to buffer failed: alloc memory failed.\n");
        fclose(file);
        return NULL;
    }

    read_size = fread(buffer, 1, file_size, file);
    fclose(file);

    if (read_size < file_size) {
        printf("Read file to buffer failed: read file content failed.\n");
        free(buffer);
        return NULL;
    }

    *size = file_size;

    return buffer;
}

static int write_to_file(const char *filename, uint8_t *buffer, uint64_t size) {
    FILE *file;
    uint64_t file_size, read_size;

    if (!filename || !buffer) {
        printf("Write file failed: invalid filename or buffer.\n");
        return -1;
    }

    file = fopen(filename, "w");
    if (file == NULL) {
        printf("Write file failed:: open file %s failed with error %d.\n",
               filename, errno);
        return -1;
    }

    if (fwrite(buffer, 1, size, file) != size) {
        printf("Write file failed:: write failed with error %d.\n",
               errno);
        return -1;
    }

    fclose(file);

    return 0;
}

/* Application entry */
int main(int argc, char *argv[])
{
    //Map between the gateway enclave id and the session information associated with that particular session
    map<sgx_enclave_id_t, dh_session_t>gateway_session_info_map;
    sgx_enclave_id_t gateway_enclave_id = 0;
    uint32_t retstatus = SUCCESS;
    dh_session_t* g_session;
    g_session = (dh_session_t *)malloc(sizeof(dh_session_t));
    if(!g_session)
        return MALLOC_ERROR;
    gateway_session_info_map.insert(pair<sgx_enclave_id_t, dh_session_t>(gateway_enclave_id, *g_session));

    retstatus = create_session(&gateway_session_info_map.find(gateway_enclave_id)->second, gateway_session_info_map.find(gateway_enclave_id)->first);
    
    if ((ATTESTATION_STATUS)retstatus != SUCCESS){
        printf("Error with ret 0x%04x", retstatus);
        return ((ATTESTATION_STATUS)retstatus);
    }

    // Loop forever until close
    while (true) {
        char path[256];
        uint8_t *buffer;
        uint64_t wasm_file_size;
        uint8_t *encrypted_wasm;
        uint64_t encrypted_wasm_size;
        
        // Read path
        printf("Service Provide: Enter WASM file: ");
        fgets(path, sizeof(path), stdin);
        path[strcspn(path, "\n")] = 0;

        if (!strncmp("exit", path, sizeof(path))) {
            printf("Service Provider: Exit requested.\n");
            break;
        }

        // Load file to buffer
        buffer = read_file_to_request(path, &wasm_file_size);
        if (buffer == NULL) {
            printf("Service Provider: Failed to read WASM file %s\n", path);
            break;
        }
        printf("file_size = %d\n", wasm_file_size);

        // Encryption
        retstatus = encrypt_payload(&gateway_session_info_map.find(gateway_enclave_id)->second, buffer,
                                                wasm_file_size, &encrypted_wasm, &encrypted_wasm_size, gateway_enclave_id);
        if ((ATTESTATION_STATUS)retstatus != SUCCESS) {
            printf("Service Provider: Encryption failed with ret 0x%04x\n", retstatus);
            free(buffer);
        }

        free(buffer);

        printf("encrypted_file_size = %d\n", encrypted_wasm_size);
        strcat(path, ".enc");
        // Write file to xxx.enc
        if (write_to_file(path, encrypted_wasm, encrypted_wasm_size)) {
            printf("Service Provider: Failed to write encrypted WASM file\n");
        }

        free(encrypted_wasm);
    }
    
    printf("process message close\n");
    retstatus = close_session(&gateway_session_info_map.find(gateway_enclave_id)->second, gateway_enclave_id);
    if ((ATTESTATION_STATUS)retstatus != SUCCESS){
        printf("Error with ret 0x%04x", retstatus);
        return ((ATTESTATION_STATUS)retstatus);
    }
    printf("process message close successs\n");
    //Erase the session context
    memset(&gateway_session_info_map.find(gateway_enclave_id)->second, 0, sizeof(dh_session_t));

    return 0;
}


