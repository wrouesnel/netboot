/*
 * Pixiecore's iPXE build configuration. "mage updateIpxe" copies this
 * directory to config/local/pixiecore/ in the iPXE source tree, and
 * builds with CONFIG=pixiecore. Settings here override iPXE's defaults
 * in config/general.h.
 */

/* Allow booting over HTTPS on BIOS, not only UEFI. */
#undef DOWNLOAD_PROTO_HTTPS
#define DOWNLOAD_PROTO_HTTPS
