using System;
using System.Collections.Generic;
using System.Text;
using System.Diagnostics;
using System.Threading;
using System.IO;
using System.Runtime.InteropServices;
using System.Reflection;

namespace Zat_s_CSGO_Dumper
{
    class Program
    {
        #region VARIABLES
        private static Dictionary<string, string> offsets;
        private const string PROCESS_NAME = "csgo";
        private static SigScanner scanner;
        private const int MAX_DUMP_SIZE = 0xFFFF;
        private static int dllClientAddress, dllEngineAddress;
        private static long dllClientSize, dllEngineSize;
        //OFfsets
        private static int localPlayer;
        #endregion

        static void Main(string[] args)
        {
            //Init & fill variables
            string line = new string('-', Console.WindowWidth);
            offsets = new Dictionary<string, string>();
            PrintSideInfo(line);

            PrintInfo("[>]=-- Zat's CSGO-Dumper v.{0}", Assembly.GetExecutingAssembly().GetName().Version.ToString());

            //Wait for process
            PrintSideInfo(line);
            PrintSideInfo("");
            PrintSideInfo(line);

            //Preparation: Gather module info
            PrintStatus("Waiting for process to spawn and load...");
            int x = Console.CursorLeft;
            int a = 0;
            do
            {
                Console.CursorLeft = x;
                Console.Write(a++ % 2 == 0.0 ? "?" : " ");
                Thread.Sleep(100);
                if (Process.GetProcessesByName(PROCESS_NAME).Length == 0)
                    continue;
                scanner = new SigScanner(Process.GetProcessesByName(PROCESS_NAME)[0], IntPtr.Zero, MAX_DUMP_SIZE);
                dllClientAddress = GetModuleBaseAddressByName(scanner.Process, @"bin\client.dll").ToInt32();
                dllEngineAddress = GetModuleBaseAddressByName(scanner.Process, @"engine.dll").ToInt32();
                dllClientSize = GetModuleSize(scanner.Process, @"bin\client.dll");
                dllEngineSize = GetModuleSize(scanner.Process, @"engine.dll");
            } while (scanner == null || dllEngineAddress == 0 || dllClientAddress == 0);
            Console.CursorLeft = x;

            PrintSideInfo("[client.dll:0x{0}:{1}]", dllClientAddress.ToString("X").PadLeft(8, '0'), ByteSizeToString(dllClientSize));
            PrintSideInfo("[engine.dll:0x{0}:{1}]", dllEngineAddress.ToString("X").PadLeft(8, '0'), ByteSizeToString(dllEngineSize));
            PrintSideInfo(line);

            //Find one offset step by step
            PrintInfo("~ General");
            PrintStatus("Scanning for EntityList...");
            FindEntityList();
            PrintStatus("Scanning for LocalPlayer...");
            FindLocalPlayer();
            PrintStatus("Scanning for FlashMaxDuration...");
            FindFlashMaxDuration();
            PrintStatus("Scanning for FindFlashMaxAlpha...");
            FindFlashMaxAlpha();
            PrintStatus("Scanning for RadarBase...");
            FindRadarBase();
            PrintStatus("Scanning for ScoreBoardBase...");
            FindScoreBoardBase();
            PrintStatus("Scanning for ServerBase...");
            FindServerBase();
            PrintStatus("Scanning for EnginePointer...");
            FindEnginePointer();
            PrintStatus("Scanning for SetViewAngles...");
            FindSetViewAngles();
            PrintStatus("Scanning for CrosshairIndex");
            FindCrosshairIndex();
            PrintStatus("Scanning for GlowObjectBase...");
            FindGlowObjectBase();
            PrintStatus("Scanning for VMatrix...");
            FindViewMatrix();
            PrintInfo("~ Controls");
            PrintStatus("Scanning for attack...");
            FindAttack();
            PrintStatus("Scanning for attack2...");
            FindAttack2();
            PrintStatus("Scanning for forward...");
            FindForward();
            PrintStatus("Scanning for backward...");
            FindBackward();
            PrintStatus("Scanning for moveright...");
            FindLeft();
            PrintStatus("Scanning for moveleft...");
            FindRight();
            PrintStatus("Scanning for jump...");
            FindJump();

            //End

            PrintSideInfo(line);
            PrintInfo("Dump finished");
            PrintStatus("* Dump finished *");
            if (offsets.Count > 0)
            {
                if (GetKeyFromUser("Would you like to save these offsets? [Y/N]", ConsoleKey.Enter, ConsoleKey.Y, ConsoleKey.N) == ConsoleKey.Y)
                {
                    SaveOffsets();
                }
            }
            PrintInfo("Press any key to exit.");
            Console.ReadKey();
        }

        #region OFFSET-METHODS
        #region GENERAL
        private static void FindEntityList()
        {
            byte[] pattern = new byte[]{ 
                0x05, 0x00, 0x00, 0x00, 0x00, //add eax, client.dll+xxxx
                0xC1, 0xe9, 0x00,                   //shr ecx, x
                0x39, 0x48, 0x04                    //cmp [eax+04], ecx
                };
            string mask = MaskFromPattern(pattern);
            int address, val1, val2;

            address = FindAddress(pattern, 1, mask, dllClientAddress, dllClientSize);
            val1 = ReadInt32(scanner.Process.Handle, address);
            address = FindAddress(pattern, 7, mask, dllClientAddress, dllClientSize);
            val2 = ReadByte(scanner.Process.Handle, address);
            val1 = val1 + val2 - dllClientAddress;

            PrintAddress("EntityList", val1);
        }
        private static void FindLocalPlayer()
        {
            byte[] pattern = new byte[]{ 
                0x8D, 0x34, 0x85, 0x00, 0x00, 0x00, 0x00,       //lea esi, [eax*4+client.dll+xxxx]
                0x89, 0x15, 0x00, 0x00, 0x00, 0x00,             //mov [client.dll+xxxx],edx
                0x8B, 0x41, 0x08,                               //mov eax,[ecx+08]
                0x8B, 0x48, 0x00                                //mov ecx,[eax+04]
                };
            string mask = MaskFromPattern(pattern);
            int address, val1, val2;

            address = FindAddress(pattern, 3, mask, dllClientAddress, dllClientSize);
            val1 = ReadInt32(scanner.Process.Handle, address);
            address = FindAddress(pattern, 18, mask, dllClientAddress, dllClientSize);
            val2 = ReadByte(scanner.Process.Handle, address);
            val1 += val2;
            val1 -= dllClientAddress;

            localPlayer = val1;
            PrintAddress("LocalPlayer", val1);
        }
        private static void FindScoreBoardBase()
        {
            //Find pointer from engine.dll
            byte[] pattern = new byte[]{ 
                0x89, 0x4D, 0xF4,                   //mov [ebp-0C],ecx
                0x8B, 0x0D, 0x00, 0x00, 0x00, 0x00, //mov ecx,[engine.dll+xxxx]
                0x53,                               //push ebx
                0x56,                               //push esi
                0x57,                               //push edi
                0x8B, 0x01                          //moveax,[ecx]
                };
            string mask = MaskFromPattern(pattern);
            int address, pointer, offset;

            address = FindAddress(pattern, 5, mask, dllEngineAddress, dllEngineSize);
            pointer = ReadInt32(scanner.Process.Handle, address);
            pointer = pointer - dllEngineAddress;

            byte[] short1 = BitConverter.GetBytes((short)(0x0004));
            pattern = new byte[]{
                0xCC,                               //int 3
                0xCC,                               //int 3
                0x55,                               //push ebp
                0x8B, 0xEC,                         //mov ebp,esp
                0x8B, 0x45, 0x08,                   //mov eax,[ebp+08]
                0x8B, 0x44, 0xC1, 0x00,             //mov eax,[acx+eax*8+xx]
                0x5D,                               //pop ebp
                0xC2, short1[0], short1[1],         //ret 0004
                0xCC,                               //int 3
                0xCC                                //int 3
            };
            mask = MaskFromPattern(pattern);

            address = FindAddress(pattern, 11, mask, dllClientAddress, dllClientSize);
            offset = ReadByte(scanner.Process.Handle, address);
            //assume constant eax 46
            address = ReadInt32(scanner.Process.Handle, dllEngineAddress + pointer); //0x46 * offset + pointer;
            address = address + 0x46 * 8 + offset;
            address -= dllClientAddress;
            PrintAddress("ScoreBoardBase/GameResources", address);
        }
        private static void FindRadarBase()
        {
            byte[] int1 = BitConverter.GetBytes(0x00100000);
            byte[] pattern = new byte[]{ 
                0xA1, 0x00, 0x00, 0x00, 0x00,                   //mov eax,[client.dll+xxxx]
                0xA9, int1[0], int1[1], int1[2], int1[3],       //test eax, 00100000
                0x74, 0x06,                                     //je client.dll+2E78C6
                0x81, 0xCE, int1[0], int1[1], int1[2], int1[3]
                };
            string mask = MaskFromPattern(pattern);
            int address, val1, val2;

            address = FindAddress(pattern, 1, mask, dllClientAddress, dllClientSize);
            val1 = ReadInt32(scanner.Process.Handle, address);

            pattern = new byte[] {
                0x8B, 0x47, 0x00,                               //mov eax,[edi+xx]
                0x8B, 0x0C, 0xB0,                               //mov ecx,[eax+esi*4]
                0x80, 0x79, 0x0D, 0x00
            };
            mask = MaskFromPattern(pattern);

            address = FindAddress(pattern, 2, mask, dllClientAddress, dllClientSize);
            val2 = ReadByte(scanner.Process.Handle, address);

            address = val1 + val2 - dllClientAddress;

            PrintAddress("RadarBase", address);
        }
        private static void FindCrosshairIndex()
        {
            if(localPlayer == 0x0)
            {
                PrintError("LocalPlayer-offset is invalid, won't find xhair this way.");
                return;
            }


            byte[] int1 = BitConverter.GetBytes(0x842A981E);
            byte[] int2 = BitConverter.GetBytes(0x682A981E);

            byte[] pattern = new byte[]{ 
                0x56,                           //push esi
                0x57,                           //push edi
                0x8B, 0xF9,                     //mov edi,ecx
                0xC7, 0x87, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  //mov [edi+xxxx], ????
                0x8B, 0x0D, 0x00, 0x00, 0x00, 0x0, //mov ecx,[client.dll+????]
                0x81, 0xF9, 0x00, 0x00, 0x00, 0x0, //cmp ecx, client.dll+????
                0x75, 0x07,                     //jne client.dll+????
                0xA1, 0x00, 0x00, 0x00, 0x00,   //mov eax,[client.dll+????]
                0xEB, 0x07                      //jmp client.dll+????
                };
            string mask = MaskFromPattern(pattern);
            int address, val1;

            address = FindAddress(pattern, 6, mask, dllClientAddress, dllClientSize);
            val1 = ReadInt32(scanner.Process.Handle, address);
            //val1 -= localPlayer;

            PrintAddress("CrosshairIndex", val1);
        }
        private static void FindServerBase()
        {
            byte[] pattern = new byte[]{
                0x81, 0xC6, 0x00, 0x00, 0x00, 0x00,
                0x81, 0xFE, 0x00, 0x00, 0x00, 0x00,
                0x7C, 0xEB,
                0x8B, 0x0D, 0x00, 0x00, 0x00, 0x00, //<<<<
                0x5F,
                0x5E,
                0x85, 0xC9,
                0x74, 0x0F,
                0x8B, 0x01,
                0xFF, 0x50, 0x04,
                0xC7, 0x05
                };
            string mask = MaskFromPattern(pattern);
            int address, val1;

            address = FindAddress(pattern, 16, mask, dllClientAddress, dllClientSize);            //Find x1
            if (address != 0)
            {
                val1 = ReadInt32(scanner.Process.Handle, address);    //Read x1
                address = val1 - dllClientAddress;
            }

            PrintAddress("ServerBase", address);
        }
        private static void FindEnginePointer()
        {
            byte[] pattern = new byte[]{
                0xC2, 0x00, 0x00,
                0xCC,
                0xCC,
                0x8B, 0x0D, 0x00, 0x00, 0x00, 0x00, //<<<<
                0x33, 0xC0,
                0x83, 0xB9
                };
            string mask = MaskFromPattern(pattern);
            int address, val1;

            address = FindAddress(pattern, 7, mask, dllEngineAddress, dllEngineSize);            //Find x1
            if (address != 0)
            {
                val1 = ReadInt32(scanner.Process.Handle, address);    //Read x1
                address = val1 - dllEngineAddress;
            }

            PrintAddress("EnginePointer", address);
        }
        private static void FindSetViewAngles()
        {
            byte[] pattern = new byte[]{ 
                0x8B, 0x15, 0x00, 0x00, 0x00, 0x00, 
                0x8B, 0x4D, 0x08,
                0x8B, 0x82, 0x00, 0x00, 0x00, 0x00, //<<<
                0x89, 0x01,
                0x8B, 0x82, 0x00, 0x00, 0x00, 0x00,
                0x89, 0x41, 0x04
                };
            string mask = MaskFromPattern(pattern);
            int address, val1;

            address = FindAddress(pattern, 11, mask, dllEngineAddress, dllEngineSize);
            val1 = ReadInt32(scanner.Process.Handle, address);

            PrintAddress("SetViewAngles", val1);
        }
        private static void FindFlashMaxDuration()
        {
            byte[] pattern = new byte[]{ 
                0x84, 0xC0,
                0x0F, 0x84, 0x00, 0x00, 0x00, 0x00,
                0xF3, 0x0F, 0x10, 0x87, 0x00, 0x00, 0x00, 0x00, //<<<
                0x0F, 0x57, 0xC9,
                0x0F, 0x2E, 0x86
                };
            string mask = MaskFromPattern(pattern);
            int address, val1;

            address = FindAddress(pattern, 12, mask, dllClientAddress, dllClientSize);
            val1 = ReadInt32(scanner.Process.Handle, address);

            PrintAddress("FlashMaxDuration", val1);
        }
        private static void FindFlashMaxAlpha()
        {
            byte[] pattern = new byte[]{ 
                0x0F, 0x2F, 0xF2,
                0x0F, 0x87, 0x00, 0x00, 0x00, 0x00,
                0xF3, 0x0F, 0x10, 0xA1, 0x00, 0x00, 0x00, 0x00, //<<<
                0x0F, 0x2F, 0xCC,
                0x0F, 0x83
                };
            string mask = MaskFromPattern(pattern);
            int address, val1;

            address = FindAddress(pattern, 13, mask, dllClientAddress, dllClientSize);
            val1 = ReadInt32(scanner.Process.Handle, address);

            PrintAddress("FlashMaxAlpha", val1);
        }
        private static void FindGlowObjectBase()
        {
            byte[] pattern = new byte[]{ 
                0x8D, 0x8F, 0x00, 0x00, 0x00, 0x00,
                0xA1, 0x00, 0x00, 0x00, 0x00, //<<<<<
                0xC7, 0x04, 0x02, 0x00, 0x00, 0x00, 0x00,
                0x89, 0x35, 0x00, 0x00, 0x00, 0x00,
                0x8B, 0x51
                };
            string mask = MaskFromPattern(pattern);
            int address, val1;

            address = FindAddress(pattern, 7, mask, dllClientAddress, dllClientSize);            //Find x1
            if (address != 0)
            {
                val1 = ReadInt32(scanner.Process.Handle, address);    //Read x1
                address = val1 - dllClientAddress;
            }
            PrintAddress("GlowObjectBase", address);
        }
        private static void FindViewMatrix()
        {
            #region Obsolete
            /*
             * http://www.unknowncheats.me/forum/1161791-post67.html
             * The user Speedi13 found a more elegant and faster way to find the vmatrices by finding the function that uses them
             * It's actually way faster than this method (user must play on a server in order to find the VMatrix this way):
             */
            //byte[] pattern = new byte[]{ 
            //                                                              0x00, 0x00, 0x80, 0xBF, /**/ 0x00, 0x00, 0x00, 0x00, /**/ //-1
            //    0x00, 0x00, 0x00, 0x00, /**/ 0x00, 0x00, 0x00, 0x00, /**/ 0x00, 0x00, 0x80, 0xBF, /**/ 0x00, 0x00, 0x00, 0x00, /**/ //-1
            //    0x00, 0x00, 0x00, 0x00, /**/ 0x00, 0x00, 0x00, 0x00, /**/ 0x00, 0x00, 0x00, 0x00, /**/ 0x00, 0x00, 0x00, 0x00, /**/ //skip
            //    0x00, 0x00, 0x00, 0x00, /**/ 0x00, 0x00, 0x00, 0x00, /**/ 0x00, 0x00, 0x00, 0x00, /**/ 0x00, 0x00, 0x00, 0x00, /**/ //skip
            //    0x00, 0x00, 0x00, 0x00, /**/ 0x00, 0x00, 0x00, 0x00, /**/ 0x00, 0x00, 0x00, 0x00, /**/ 0x00, 0x00, 0x80, 0xBF  /**/ //-1
            //    };

            //string mask =                               "??xx" + /**/ "????" + //-1
            //                "xxxx" + /**/ "xxxx" + /**/ "??xx" + /**/ "xxxx" + //-1
            //                "????" + /**/ "????" + /**/ "????" + /**/ "????" + //skip
            //                "????" + /**/ "????" + /**/ "????" + /**/ "????" + //skip
            //                "????" + /**/ "????" + /**/ "????" + /**/ "??xx";  //-1


            //address = FindAddress(pattern, 0, mask, dllClientAddress, dllClientSize);
            //address += 22 * sizeof(float);
            //address -= dllClientAddress;
            #endregion

            int address = 0;
            byte[] pattern = {
                                0x53, 0x8B, 0xDC, 0x83, 0xEC, 0x08, 0x83, 0xE4,
                                0xF0, 0x83, 0xC4, 0x04, 0x55, 0x8B, 0x6B, 0x04,
                                0x89, 0x6C, 0x24, 0x04, 0x8B, 0xEC, 0xA1, 0x00,
                                0x00, 0x00, 0x00, 0x81, 0xEC, 0x98, 0x03, 0x00,
                                0x00
                                };
            address = FindAddress(pattern, 0, "xxxxxxxxxxxxxxxxxxxxxxx????xxxxxx", dllClientAddress, dllClientSize);
            if(address == 0)
            {
                Program.PrintError("Could not find VMatrices! (nullpointer)");
                offsets.Add("[VMatrices nullptr]", string.Empty);
                return;
            }
            address = ReadInt32(scanner.Process.Handle, address + 0x4EE);
            address -= dllClientAddress;
            address += 0x80;

            PrintAddress("ViewMatrix1", address);
            PrintAddress("ViewMatrix2", address + 0x110); //VMatrix2 and 3 got a fixed distance to VMatrix1 - Simply add the distances to the address.
            PrintAddress("ViewMatrix3", address + 0x420);
        }
        #endregion
        #region CONTROLS
        private static void FindAttack()
        {
            byte[] int1 = BitConverter.GetBytes(0xFFFFFFFD);
            byte[] pattern = new byte[]{ 
                0x89, 0x15, 0x00, 0x00, 0x00, 0x00, //mov [client.dll+xxxx],edx
                0x8B, 0x15, 0x00, 0x00, 0x00, 0x00, //mov edx, [client.dll+????]
                0xF6, 0xC2, 0x03,                   //test dl, 03
                0x74, 0x03,                         //je client.dll+???? 
                0x83, 0xCE, 0x04,                   //or esi,04
                0xA8, 0x04,                         //test al,04
                0xBF, int1[0], int1[1], int1[2], int1[3]        //mov edi,FFFFFFFD
                };
            string mask = MaskFromPattern(pattern);
            int address, val1;

            address = FindAddress(pattern, 2, mask, dllClientAddress, dllClientSize);            //Find x1
            if (address != 0)
            {
                val1 = ReadInt32(scanner.Process.Handle, address);    //Read x1
                address = val1 - dllClientAddress;
            }

            PrintAddress("attack", address);
        }
        private static void FindAttack2()
        {
            byte[] int1 = BitConverter.GetBytes(0xFFFFFFFD);
            byte[] int2 = BitConverter.GetBytes(0x00002000);
            byte[] pattern = new byte[]{ 
                0x89, 0x15, 0x00, 0x00, 0x00, 0x00, //mov [client.dll+xxxx],edx
                0x8B, 0x15, 0x00, 0x00, 0x00, 0x00, //mov edx, [client.dll+????]
                0xF6, 0xC2, 0x03,                   //test dl, 03
                0x74, 0x06,                         //je client.dll+???? 
                0x81, 0xCE, int2[0], int2[1], int2[2], int2[3], //or esi,00002000
                0xA9,  int2[0], int2[1], int2[2], int2[3],      //test al,00002000
                0xBF, int1[0], int1[1], int1[2], int1[3]        //mov edi,FFFFFFFD
                };
            string mask = MaskFromPattern(pattern);
            int address, val1;

            address = FindAddress(pattern, 2, mask, dllClientAddress, dllClientSize);            //Find x1
            if (address != 0)
            {
                val1 = ReadInt32(scanner.Process.Handle, address);    //Read x1
                address = val1 - dllClientAddress;
            }

            PrintAddress("attack2", address);
        }
        private static void FindForward()
        {
            byte[] int1 = BitConverter.GetBytes(0xFFFFFFFD);
            byte[] pattern = new byte[]{ 
                0x8B, 0x15, 0x00, 0x00, 0x00, 0x00, //mov edx,[client.dll+xxxx]
                0xF6, 0xC2, 0x03,                   //test dl, 03
                0x74, 0x03,                         //je client.dll+???? 
                0x83, 0xCE, 0x08, //or esi,08
                0xA8, 0x08,       //test al,08
                0xBF, int1[0], int1[1], int1[2], int1[3]        //mov edi,FFFFFFFD
                };
            string mask = MaskFromPattern(pattern);
            int address, val1;

            address = FindAddress(pattern, 2, mask, dllClientAddress, dllClientSize);            //Find x1
            if (address != 0)
            {
                val1 = ReadInt32(scanner.Process.Handle, address);    //Read x1
                address = val1 - dllClientAddress;
            }

            PrintAddress("forward", address);
        }
        private static void FindBackward()
        {
            byte[] int1 = BitConverter.GetBytes(0xFFFFFFFD);
            byte[] pattern = new byte[]{ 
                0x8B, 0x15, 0x00, 0x00, 0x00, 0x00, //mov edx,[client.dll+xxxx]
                0xF6, 0xC2, 0x03,                   //test dl, 03
                0x74, 0x03,                         //je client.dll+???? 
                0x83, 0xCE, 0x10,                   //or esi,10
                0xA8, 0x10,                         //test al,10
                0xBF, int1[0], int1[1], int1[2], int1[3]        //mov edi,FFFFFFFD
                };
            string mask = MaskFromPattern(pattern);
            int address, val1;

            address = FindAddress(pattern, 2, mask, dllClientAddress, dllClientSize);            //Find x1
            if (address != 0)
            {
                val1 = ReadInt32(scanner.Process.Handle, address);    //Read x1
                address = val1 - dllClientAddress;
            }

            PrintAddress("backward", address);
        }
        private static void FindLeft()
        {
            byte[] int1 = BitConverter.GetBytes(0xFFFFFFFD);
            byte[] int2 = BitConverter.GetBytes(0x00000400);
            byte[] pattern = new byte[]{ 
                0x89, 0x15, 0x00, 0x00, 0x00, 0x00, //mov [client.dll+xxxx],edx
                0x8B, 0x15, 0x00, 0x00, 0x00, 0x00, //mov edx, [client.dll+????]
                0xF6, 0xC2, 0x03,                   //test dl, 03
                0x74, 0x06,                         //je client.dll+???? 
                0x81, 0xCE, int2[0], int2[1], int2[2], int2[3], //or esi,00002000
                0xA9,  int2[0], int2[1], int2[2], int2[3],      //test al,00002000
                0xBF, int1[0], int1[1], int1[2], int1[3]        //mov edi,FFFFFFFD
                };
            string mask = MaskFromPattern(pattern);
            int address, val1;

            address = FindAddress(pattern, 2, mask, dllClientAddress, dllClientSize);            //Find x1
            if (address != 0)
            {
                val1 = ReadInt32(scanner.Process.Handle, address);    //Read x1
                address = val1 - dllClientAddress;
            }

            PrintAddress("moveleft", address);
        }
        private static void FindRight()
        {
            byte[] int1 = BitConverter.GetBytes(0xFFFFFFFD);
            byte[] int2 = BitConverter.GetBytes(0x00000800);
            byte[] pattern = new byte[]{ 
                0x89, 0x15, 0x00, 0x00, 0x00, 0x00, //mov [client.dll+xxxx],edx
                0x8B, 0x15, 0x00, 0x00, 0x00, 0x00, //mov edx, [client.dll+????]
                0xF6, 0xC2, 0x03,                   //test dl, 03
                0x74, 0x06,                         //je client.dll+???? 
                0x81, 0xCE, int2[0], int2[1], int2[2], int2[3], //or esi,00002000
                0xA9,  int2[0], int2[1], int2[2], int2[3],      //test al,00002000
                0xBF, int1[0], int1[1], int1[2], int1[3]        //mov edi,FFFFFFFD
                };
            string mask = MaskFromPattern(pattern);
            int address, val1;

            address = FindAddress(pattern, 2, mask, dllClientAddress, dllClientSize);            //Find x1
            if (address != 0)
            {
                val1 = ReadInt32(scanner.Process.Handle, address);    //Read x1
                address = val1 - dllClientAddress;
            }

            PrintAddress("moveright", address);
        }
        private static void FindJump()
        {
            byte[] int1 = BitConverter.GetBytes(0xFFFFFFFD);
            byte[] pattern = new byte[]{ 
                0x89, 0x15, 0x00, 0x00, 0x00, 0x00, //mov [client.dll+xxxx],edx
                0x8B, 0x15, 0x00, 0x00, 0x00, 0x00, //mov edx,[client.dll+xxxx]
                0xF6, 0xC2, 0x03,                   //test dl, 03
                0x74, 0x03,                         //je client.dll+???? 
                0x83, 0xCE, 0x08, //or esi,08
                0xA8, 0x08,       //test al,08
                0xBF, int1[0], int1[1], int1[2], int1[3]        //mov edi,FFFFFFFD
                };
            string mask = MaskFromPattern(pattern);
            int address, val1;

            address = FindAddress(pattern, 2, mask, dllClientAddress, dllClientSize);            //Find x1
            if (address != 0)
            {
                val1 = ReadInt32(scanner.Process.Handle, address);    //Read x1
                address = val1 - dllClientAddress;
            }
            PrintAddress("jump", address);
        }
        #endregion
        #endregion

        #region HELPERS
        /// <summary>
        /// Promts the user to press a key.
        /// Keeps prompting until user enters a key that is contained in 'keys'.
        /// Returns the pressed key.
        /// </summary>
        /// <param name="message"></param>
        /// <param name="defaultKey"></param>
        /// <param name="keys"></param>
        /// <returns></returns>
        private static ConsoleKey GetKeyFromUser(string message, ConsoleKey defaultKey, params ConsoleKey[] keys)
        {
            List<ConsoleKey> lKeys = new List<ConsoleKey>(keys);
            ConsoleKey key = defaultKey;
            PrintInfo(message);
            do
            {
                key = Console.ReadKey().Key;
            } while (!lKeys.Contains(key));
            Console.WriteLine();
            return key;
        }

        /// <summary>
        /// Creates a mask of the given pattern, 
        /// making 0x00's wildcards ('?') and anything else exact matches ('x')
        /// </summary>
        /// <param name="pattern"></param>
        /// <returns></returns>
        private static string MaskFromPattern(byte[] pattern)
        {
            StringBuilder builder = new StringBuilder();
            foreach (byte data in pattern)
                if (data == 0x00)
                    builder.Append('?');
                else
                    builder.Append('x');
            return builder.ToString();
        }
        private static string ExtendSimplePattern(string pattern, int length)
        {
            StringBuilder builder = new StringBuilder();
            foreach (char chr in pattern)
                builder.Append(chr, length);
            return builder.ToString();
        }
        /// <summary>
        /// Creates a pattern of the given mask,
        /// translating 'x' to valX and everything else (wildcards) to valW
        /// </summary>
        /// <param name="mask"></param>
        /// <param name="valX"></param>
        /// <param name="valW"></param>
        /// <returns></returns>
        private static byte[] PatternFromMask(string mask, byte valX, byte valW)
        {
            byte[] pattern = new byte[mask.Length];
            
            for(int i = 0; i < pattern.Length; i++)
            {
                if (mask[i] == 'x')
                    pattern[i] = valX;
                else
                    pattern[i] = valW;
            }

            return pattern;
        }
        /// <summary>
        /// Wraps the SigScanner
        /// </summary>
        /// <param name="pattern"></param>
        /// <param name="offset"></param>
        /// <param name="mask"></param>
        /// <param name="dllAddress"></param>
        /// <param name="dllSize"></param>
        /// <param name="wNonZero"></param>
        /// <returns></returns>
        private static int FindAddress(byte[] pattern, int offset, string mask, int dllAddress, long dllSize, bool wNonZero = false)
        {
            int address = 0;
            for (int i = 0; i < dllSize && address == 0; i += MAX_DUMP_SIZE)
            {
                scanner.Address = new IntPtr(dllAddress + i);
                address = scanner.FindPattern(pattern, mask, offset, wNonZero).ToInt32();
                scanner.ResetRegion();
            }

            return address;
        }
        /// <summary>
        /// Saves the offsets contained in 'offsets' to file
        /// </summary>
        private static void SaveOffsets()
        {
            try
            {
                string line = new String('-', 20);
                using (StreamWriter writer = new StreamWriter("Zat's Offsets.txt", true))
                {
                    writer.WriteLine(line);
                    writer.WriteLine("[>]=-- Zat's CSGO-Dumper");
                    writer.WriteLine("Dumped {0}, {1}", DateTime.Now.ToShortDateString(), DateTime.Now.ToLongTimeString());
                    writer.WriteLine(line);
                    foreach (string key in offsets.Keys)
                        if (offsets[key] != string.Empty)
                            writer.WriteLine(" {0} = {1}", key, offsets[key]);
                        else
                            writer.WriteLine(" {0}", key);
                    writer.WriteLine();
                }
                PrintInfo(" > Offsets saved.");
            }
            catch (Exception ex)
            {
                PrintError("An error occured: {0}", ex.Message);
            }
        }
        /// <summary>
        /// Converts a size in bytes to a more readable size
        /// </summary>
        /// <param name="size"></param>
        /// <returns></returns>
        private static string ByteSizeToString(long size)
        {
            string[] sizes = new string[] { "B", "KB", "MB", "GB", "TB" };
            int index = 0;
            while (size > 1024)
            {
                size /= 1024;
                index++;
            }
            return string.Format("{0}{1}", size.ToString(), sizes[index]);
        }

        #region PRINT-STUFF
        private static void PrintError(string message, params string[] parameters)
        {
            PrintColorized(ConsoleColor.Red, message, parameters);
        }
        private static void PrintInfo(string message, params string[] parameters)
        {
            PrintColorized(ConsoleColor.Gray, message, parameters);
        }
        private static void PrintSideInfo(string message, params string[] parameters)
        {
            PrintColorized(ConsoleColor.DarkGray, message, parameters);
        }
        private static void PrintAddress(string name, int value)
        {
            string output = string.Format("0x{0}", value.ToString("X").PadLeft(8, '0'));
            offsets.Add(name, output);
            PrintSideInfo(" {0} {1}", name, output);
        }
        private static void PrintStatus(string status, params string[] parameters)
        {
            ClearStatus();
            int x = Console.CursorLeft, y = Console.CursorTop;
            Console.SetCursorPosition(0, 3);
            PrintColorized(ConsoleColor.Gray, string.Format("Status: {0}", status), parameters);
            Console.SetCursorPosition(x, y);
        }
        private static void ClearStatus()
        {
            int x = Console.CursorLeft, y = Console.CursorTop;
            Console.SetCursorPosition(0, 3);
            //PrintColorized(ConsoleColor.Gray, "Status: /");
            for (int i = 0; i < Console.WindowWidth; i++)
                Console.Write(" ");
            Console.SetCursorPosition(x, y);
        }
        private static void PrintColorized(ConsoleColor color, string message, params string[] parameters)
        {
            ConsoleColor tmpColor = Console.ForegroundColor;
            Console.ForegroundColor = color;
            Console.WriteLine(message, parameters);
            Console.ForegroundColor = tmpColor;
        }
        #endregion

        #region MODULE-STUFF
        private static ProcessModule GetModuleByName(Process process, string name)
        {
            try
            {
                foreach (ProcessModule module in process.Modules)
                {
                    if (module.FileName.EndsWith(name))
                        return module;
                }
            }
            catch { }
            return null;
        }
        private static long GetModuleSize(Process process, string name)
        {
            ProcessModule module = GetModuleByName(process, name);
            if (module != null)
                return module.ModuleMemorySize;
            return 0L;
        }
        private static IntPtr GetModuleBaseAddressByName(Process process, string name)
        {
            ProcessModule module = GetModuleByName(process, name);
            if (module != null)
                return module.BaseAddress;
            return IntPtr.Zero;
        }
        #endregion
        #endregion

        #region WINAPI & MEMORY-STUFF
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool ReadProcessMemory(
            IntPtr hProcess,
            IntPtr lpBaseAddress,
            [Out] byte[] lpBuffer,
            int dwSize,
            out IntPtr lpNumberOfBytesRead);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool WriteProcessMemory(
            IntPtr hProcess,
            IntPtr lpBaseAddress,
            byte[] lpBuffer,
            int dwSize,
            out IntPtr lpNumberOfBytesWritten);

        public static Int32 ReadInt32(IntPtr handle, Int64 address)
        {
            byte[] buffer = new byte[4];
            ReadMemory(handle, address, ref buffer);
            return BitConverter.ToInt32(buffer, 0);
        }
        public static Int32 ReadByte(IntPtr handle, Int64 address)
        {
            byte[] buffer = new byte[1];
            ReadMemory(handle, address, ref buffer);
            return buffer[0];
        }
        public static void ReadMemory(IntPtr handle, Int64 address, ref Byte[] buffer)
        {
            IntPtr bytesRead = IntPtr.Zero;
            ReadProcessMemory(handle, (IntPtr)address, buffer, buffer.Length, out bytesRead);
        }
        public static int WriteMemory(IntPtr hProcess, int address, byte[] lpBuffer, int dwSize)
        {
            IntPtr _bytesWritten = IntPtr.Zero;
            WriteProcessMemory(hProcess, (IntPtr)address, lpBuffer, dwSize, out _bytesWritten);
            return _bytesWritten.ToInt32();
        }
        public static int WriteMemory(IntPtr hProcess, int address, byte[] lpBuffer)
        {
            return WriteMemory(hProcess, address, lpBuffer, lpBuffer.Length);
        }
        public static int WriteInt(IntPtr hProcess, int address, int value)
        {
            return WriteMemory(hProcess, address, BitConverter.GetBytes(value), sizeof(int));
        }
        #endregion
    }
}
