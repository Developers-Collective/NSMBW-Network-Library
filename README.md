# Network Library v1.0
*network and ssl code by bushing, adjusted by MrBean35000vr and Chadderz for netslug-wii and adjusted again for use in NSMBW mods by Nin0*

*http code by ibrahima, adjusted for use in NSMBW mods by Nin0*

- Orginal code can be found in [libogc](https://github.com/devkitPro/libogc/blob/master/libogc/network_wii.c)
- Adjusted version can be found in [netslug-wii](https://github.com/MrBean35000vr/netslug-wii/blob/master/modules/netslug_main/network_wii.c)
- Original ssl code can be found on [wiibrew](https://wiibrew.org/wiki//dev/net/ssl/code)
- Original code for http requests can be found in the [wiihttp](https://github.com/ibrahima/wiihttp/tree/master) repo


The library was tested with [NSMBWer+](https://github.com/Developers-Collective/NSMBWerPlus)!

## Important
The Wii's SSL library does not support secure TLS versions. Not using any encryption and/or signatures may lead to RCE (remote code execution) potentially allowing people to brick a users Wii or even install malware on it and other devices on a network. Discussion about encryption and signature scheme implementation is on going on NHD, Horizon, Evolution and the NSMLW Discord servers. Feel free to join us in coming up with solutions for these issues.

## Explanation
This code allows to start TCP connections from within New Super Mario Bros. Wii! It further provides a simple code example how to download a file from a HTTP server. Downloading files over SSL/TLS is not directly supported, for reasons listed below. However, this repo contains the SSL code found on wiibrew for completeness sake.

## Kamek
- Add `include/IOS.h` in your `include` folder
- Add everything from `src/network/` in a new `src/network/` folder
- Add `network.yaml` in your `Kamek` folder
- Add `network.yaml` in the `project.yaml` file referencing all other `.yaml` files
- Add these addresses to your `kamek_pal.x`:
```cpp
	IOS_Open__FPci = 0x80224db0;
	IOS_Close__Fi = 0x80224fa0;
	IOS_Ioctlv__FiiiiPv = 0x80225ae0;
	IOS_Ioctl__FiiPvUlPvUl = 0x80225780;
	__iosAlloc = 0x80225ff0;
	strnlen = 0x802244d0;
	memset__FPviUl = 0x800046b4;
	strchr = 0x802e1f00;
	atoi = 0x802E23F8;
```
- Compile your code

## Usage
In `network.yaml` there is a hook causing the function `testNetwork()` in `network_wii.cpp` to be called whenever a player jumps for demonstration. Remove the hook after understanding how the example works.

The `testNetwork()` function first initializes the Wii to be able to interact with the network. This happens by calling `ìnit()`. If this call is successful, a file is downloaded using the function `downloadFile(const char *url)`. This function returns either a pointer to the downloaded file in memory or `NULL` if it was unsuccessful, for example due to the file being too large for the heap memory to contain it. Memory of pointers returned by this function must be freed at some point using the `FreeFromGameHeap1(void* ptr)` function, in order to prevent memory leakage.

There is two commented-out functions in `network_wii.cpp`. One is called `displaySSLInetFile` and demonstrates the usage of the ssl code from wiibrew. I gave up on getting this to work for my domain however, as it appears the Wii does not support modern SSL/TLS versions, making the library useless for web servers that do not support the old versions the Wii does support. Follow [this](https://wiibrew.org/wiki//dev/net/ssl) page to find explanations on how this is supposed to be set up and used. The other function is called `displayInetFile` and works similar to the `downloadFile` function, except that it only displays the content of the url with OSReports without returning a pointer to the file, but instead just a success/failure value.

## Other
If there is a compilation or a game problem, tell me, maybe I forgot something somewhere.
