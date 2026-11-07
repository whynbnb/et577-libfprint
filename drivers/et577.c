/*
 * Egis Technology Inc. EH577 (ET300) driver for libfprint
 *
 * Protocol reverse-engineered from the Windows UMDF driver (ETU813 3.6.2.3)
 * and verified with a USBPcap capture of the Windows driver.
 *
 * Key facts:
 *  - One image capture is a single bulk IN read of 3990 bytes.
 *  - 3990 bytes decode to a 70 x 57 grayscale image (row-major).
 *    (Autocorrelation of the vertical direction has a strong peak at lag 70.)
 *  - The sensor is a small press/area sensor (~5 x 4 mm).  NBIS/Bozorth3 only
 *    finds 3-9 minutiae per press, which is below Bozorth3's hard minimum of
 *    10, so this driver implements its own host-side matcher.
 *  - The matcher compares 16x16 normalized patches over a small rotation
 *    search and requires both a minimum number of matching patches and a
 *    minimum number of patches that agree on the same spatial translation
 *    ("consensus").  This tolerates partial overlap, which is unavoidable
 *    with such a small sensor.
 *  - Finger presence is detected with the device's own poll command; images
 *    are only captured in short bursts (start sequence, 3 frames, stop
 *    sequence).  Never keep the sensor in a continuous capture loop: the
 *    firmware can lock up.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * WARNING / DISCLAIMER:
 *  This driver is intended for everyday convenience only (desktop unlock,
 *  login).  The sensor is very small and the host-side matcher is heuristic.
 *  Accuracy is not guaranteed: both false accepts (another finger or region)
 *  and false rejects (the enrolled finger) are possible.  Do not rely on it
 *  for high-security use.
 */

#define FP_COMPONENT "et577"

#include <math.h>
#include "drivers_api.h"

#define ET577_VID 0x1c7a
#define ET577_PID 0x0577

#define ET577_EPOUT 0x01
#define ET577_EPIN  0x82

#define ET577_TIMEOUT 5000

#define ET577_WIDTH  70
#define ET577_HEIGHT 57
#define ET577_IMGSIZE (ET577_WIDTH * ET577_HEIGHT) /* 3990 */

#define ET577_ENROLL_STAGES 6
#define ET577_MAX_TEMPLATES 32

/* press detection thresholds (standard deviation of the raw image) */
#define ET577_PRESS_STD   12.0
#define ET577_RELEASE_STD  7.0

/* matching parameters */
#define ET577_MATCH_THRESHOLD 20.0  /* minimum spatially consistent patches */
#define ET577_RAW_MIN         40.0  /* minimum raw patch matches */
#define ET577_PATCH          16
#define ET577_PATCH_STRIDE    4
#define ET577_PATCH_MAX     200
#define ET577_PATCH_DIM      (ET577_PATCH * ET577_PATCH)
#define ET577_PATCH_MIN_STD   6.0
#define ET577_PATCH_GOOD      0.75
#define ET577_ANGLE_STEP      5.0
#define ET577_ANGLE_RANGE    20.0

#define ET577_TEMPLATE_MAGIC0 'E'
#define ET577_TEMPLATE_MAGIC1 'T'
#define ET577_TEMPLATE_MAGIC2 '5'
#define ET577_TEMPLATE_MAGIC3 '7'
#define ET577_TEMPLATE_VERSION 1

/* Calibration data captured from the Windows driver */
static const guint8 et577_calib_data[] = {
#include "et577_calib_data.h"
};

/* Init1 sequence */
static const struct { const guint8 *data; int len; } et577_init1[] = {
  { (const guint8[]){0x45,0x47,0x49,0x53,0x60,0x00,0xfc}, 7 },
  { (const guint8[]){0x45,0x47,0x49,0x53,0x60,0x01,0xfc}, 7 },
  { (const guint8[]){0x45,0x47,0x49,0x53,0x60,0x00,0xfc}, 7 },
  { (const guint8[]){0x45,0x47,0x49,0x53,0x60,0x01,0xfc}, 7 },
  { (const guint8[]){0x45,0x47,0x49,0x53,0x61,0x0a,0xfd}, 7 },
  { (const guint8[]){0x45,0x47,0x49,0x53,0x61,0x35,0x02}, 7 },
  { (const guint8[]){0x45,0x47,0x49,0x53,0x61,0x80,0x00}, 7 },
  { (const guint8[]){0x45,0x47,0x49,0x53,0x60,0x80,0x00}, 7 },
  { (const guint8[]){0x45,0x47,0x49,0x53,0x61,0x0a,0xfc}, 7 },
  { (const guint8[]){0x45,0x47,0x49,0x53,0x63,0x01,0x02,0x0f,0x03}, 9 },
  { (const guint8[]){0x45,0x47,0x49,0x53,0x61,0x0c,0x22}, 7 },
  { (const guint8[]){0x45,0x47,0x49,0x53,0x61,0x09,0x83}, 7 },
  { (const guint8[]){0x45,0x47,0x49,0x53,0x63,0x26,0x06,0x0e,0x36,0x04,0x0a,0x2e,0x04}, 13 },
  { (const guint8[]){0x45,0x47,0x49,0x53,0x61,0x0a,0xf4}, 7 },
  { (const guint8[]){0x45,0x47,0x49,0x53,0x61,0x0c,0x44}, 7 },
  { (const guint8[]){0x45,0x47,0x49,0x53,0x61,0x50,0x03}, 7 },
  { (const guint8[]){0x45,0x47,0x49,0x53,0x60,0x50,0x03}, 7 },
};
#define ET577_INIT1_COUNT G_N_ELEMENTS (et577_init1)

/* Calibration trigger command */
static const guint8 et577_calib_cmd[] = { 0x45,0x47,0x49,0x53,0x73,0x0f,0x96 };

/* Init2 sequence */
static const struct { const guint8 *data; int len; } et577_init2[] = {
  { (const guint8[]){0x45,0x47,0x49,0x53,0x60,0x40,0x96}, 7 },
  { (const guint8[]){0x45,0x47,0x49,0x53,0x61,0x0c,0x22}, 7 },
  { (const guint8[]){0x45,0x47,0x49,0x53,0x61,0x0b,0x03}, 7 },
  { (const guint8[]){0x45,0x47,0x49,0x53,0x61,0x0a,0xfc}, 7 },
  { (const guint8[]){0x45,0x47,0x49,0x53,0x60,0x40,0xfc}, 7 },
  { (const guint8[]){0x45,0x47,0x49,0x53,0x63,0x09,0x0b,0x83,0x24,0x00,0x44,0x0f,0x08,0x20,0x20,0x01,0x05,0x12}, 18 },
  { (const guint8[]){0x45,0x47,0x49,0x53,0x63,0x26,0x06,0x0e,0x36,0x04,0x0a,0x2e,0x04}, 13 },
  { (const guint8[]){0x45,0x47,0x49,0x53,0x61,0x23,0x00}, 7 },
  { (const guint8[]){0x45,0x47,0x49,0x53,0x61,0x24,0x38}, 7 },
  { (const guint8[]){0x45,0x47,0x49,0x53,0x61,0x20,0x00}, 7 },
  { (const guint8[]){0x45,0x47,0x49,0x53,0x61,0x21,0x45}, 7 },
  { (const guint8[]){0x45,0x47,0x49,0x53,0x60,0x00,0x45}, 7 },
  { (const guint8[]){0x45,0x47,0x49,0x53,0x60,0x01,0x45}, 7 },
  { (const guint8[]){0x45,0x47,0x49,0x53,0x63,0x2c,0x02,0x00,0x57}, 9 },
  { (const guint8[]){0x45,0x47,0x49,0x53,0x60,0x2d,0x02}, 7 },
  { (const guint8[]){0x45,0x47,0x49,0x53,0x62,0x67,0x03}, 7 },
  { (const guint8[]){0x45,0x47,0x49,0x53,0x60,0x0f,0x03}, 7 },
  { (const guint8[]){0x45,0x47,0x49,0x53,0x63,0x2c,0x02,0x00,0x13}, 9 },
  { (const guint8[]){0x45,0x47,0x49,0x53,0x60,0x00,0x02}, 7 },
};
#define ET577_INIT2_COUNT G_N_ELEMENTS (et577_init2)

/* Repeat sequence sent before each additional image capture */
static const struct { const guint8 *data; int len; } et577_repeat[] = {
  { (const guint8[]){0x45,0x47,0x49,0x53,0x61,0x2d,0x20}, 7 },
  { (const guint8[]){0x45,0x47,0x49,0x53,0x60,0x00,0x20}, 7 },
  { (const guint8[]){0x45,0x47,0x49,0x53,0x60,0x01,0x20}, 7 },
  { (const guint8[]){0x45,0x47,0x49,0x53,0x63,0x2c,0x02,0x00,0x57}, 9 },
  { (const guint8[]){0x45,0x47,0x49,0x53,0x60,0x2d,0x02}, 7 },
  { (const guint8[]){0x45,0x47,0x49,0x53,0x62,0x67,0x03}, 7 },
  { (const guint8[]){0x45,0x47,0x49,0x53,0x63,0x2c,0x02,0x00,0x13}, 9 },
  { (const guint8[]){0x45,0x47,0x49,0x53,0x60,0x00,0x02}, 7 },
};
#define ET577_REPEAT_COUNT G_N_ELEMENTS (et577_repeat)

/* Image capture command */
static const guint8 et577_image_cmd[] = { 0x45,0x47,0x49,0x53,0x64,0x0f,0x96 };

/* Sequence started after the poll reports a finger.  Captured from the
 * Windows driver. */
static const struct { const guint8 *data; int len; } et577_start_burst[] = {
  { (const guint8[]){0x45,0x47,0x49,0x53,0x60,0x40,0x06}, 7 },
  { (const guint8[]){0x45,0x47,0x49,0x53,0x61,0x0a,0xf4}, 7 },
  { (const guint8[]){0x45,0x47,0x49,0x53,0x61,0x0c,0x44}, 7 },
  { (const guint8[]){0x45,0x47,0x49,0x53,0x61,0x40,0x00}, 7 },
  { (const guint8[]){0x45,0x47,0x49,0x53,0x60,0x40,0x00}, 7 },
  { (const guint8[]){0x45,0x47,0x49,0x53,0x71,0x02,0x02,0x01,0x0c}, 9 },
  { (const guint8[]){0x45,0x47,0x49,0x53,0x63,0x09,0x0b,0x83,0x24,0x00,0x44,0x0f,0x08,0x20,0x20,0x01,0x05,0x12}, 18 },
  { (const guint8[]){0x45,0x47,0x49,0x53,0x63,0x26,0x06,0x0e,0x36,0x04,0x0a,0x2e,0x04}, 13 },
  { (const guint8[]){0x45,0x47,0x49,0x53,0x61,0x23,0x00}, 7 },
  { (const guint8[]){0x45,0x47,0x49,0x53,0x61,0x24,0x38}, 7 },
  { (const guint8[]){0x45,0x47,0x49,0x53,0x61,0x20,0x00}, 7 },
  { (const guint8[]){0x45,0x47,0x49,0x53,0x61,0x21,0x45}, 7 },
  { (const guint8[]){0x45,0x47,0x49,0x53,0x60,0x00,0x45}, 7 },
  { (const guint8[]){0x45,0x47,0x49,0x53,0x60,0x01,0x45}, 7 },
  { (const guint8[]){0x45,0x47,0x49,0x53,0x63,0x2c,0x02,0x00,0x57}, 9 },
  { (const guint8[]){0x45,0x47,0x49,0x53,0x60,0x2d,0x02}, 7 },
  { (const guint8[]){0x45,0x47,0x49,0x53,0x62,0x67,0x03}, 7 },
  { (const guint8[]){0x45,0x47,0x49,0x53,0x60,0x0f,0x03}, 7 },
  { (const guint8[]){0x45,0x47,0x49,0x53,0x63,0x2c,0x02,0x00,0x13}, 9 },
  { (const guint8[]){0x45,0x47,0x49,0x53,0x60,0x00,0x02}, 7 },
};
#define ET577_START_BURST_COUNT G_N_ELEMENTS (et577_start_burst)

/* Sequence that ends a burst and returns the sensor to finger-poll mode. */
static const struct { const guint8 *data; int len; } et577_stop_burst[] = {
  { (const guint8[]){0x45,0x47,0x49,0x53,0x61,0x2d,0x20}, 7 },
  { (const guint8[]){0x45,0x47,0x49,0x53,0x60,0x40,0x20}, 7 },
  { (const guint8[]){0x45,0x47,0x49,0x53,0x63,0x26,0x06,0x0e,0x36,0x04,0x0a,0x2e,0x04}, 13 },
  { (const guint8[]){0x45,0x47,0x49,0x53,0x63,0x09,0x0b,0x83,0xf4,0x03,0x44,0x03,0x0d,0x14,0x20,0x01,0x0a,0x72}, 18 },
  { (const guint8[]){0x45,0x47,0x49,0x53,0x63,0x01,0x02,0x0c,0x03}, 9 },
  { (const guint8[]){0x45,0x47,0x49,0x53,0x61,0x0c,0x22}, 7 },
  { (const guint8[]){0x45,0x47,0x49,0x53,0x61,0x0b,0x03}, 7 },
  { (const guint8[]){0x45,0x47,0x49,0x53,0x61,0x0a,0xfc}, 7 },
  { (const guint8[]){0x45,0x47,0x49,0x53,0x71,0x45,0x06,0x00,0xcb,0x87,0x13,0x00,0x03}, 13 },
};
#define ET577_STOP_BURST_COUNT G_N_ELEMENTS (et577_stop_burst)

/* Finger presence poll.  Response byte 5 is 0x04 when a finger is present
 * and 0x00 otherwise. */
static const guint8 et577_poll_cmd[] = { 0x45,0x47,0x49,0x53,0x60,0x01,0x06 };
#define ET577_POLL_FINGER_PRESENT 0x04

typedef struct _FpDeviceEt577
{
  FpDevice parent;

  GMutex io_lock;
  GCond io_cond;
  gboolean worker_running;
  GCancellable *cancellable;
  guint watchdog_id;
  gboolean initialized;
  gboolean init_had_finger;

  guint8 captured[ET577_IMGSIZE];
  gdouble captured_std;
  guint8 burst_images[3][ET577_IMGSIZE];
  guint burst_count;

  GByteArray *enroll_images;
  guint enroll_stages_passed;

  gint match_score;      /* best score * 1000 */
  gint match_index;      /* best template / print index */
} FpDeviceEt577;

G_DECLARE_FINAL_TYPE (FpDeviceEt577, fpi_device_et577, FPI, DEVICE_ET577, FpDevice);
G_DEFINE_TYPE (FpDeviceEt577, fpi_device_et577, FP_TYPE_DEVICE);

/* ------------------------------------------------------------------ */
/* USB helpers (blocking; called from worker threads)                  */
/* ------------------------------------------------------------------ */

static gdouble et577_image_std (const guint8 *image);

static gboolean
et577_usb_write (FpDeviceEt577 *self, const guint8 *data, gsize len,
                 GCancellable *cancellable, GError **error)
{
  gsize actual = 0;
  GUsbDevice *usb = fpi_device_get_usb_device (FP_DEVICE (self));

  if (!g_usb_device_bulk_transfer (usb, ET577_EPOUT, (guint8 *) data, len,
                                   &actual, ET577_TIMEOUT, cancellable, error))
    {
      /* This device reports an overflow ("device sent more data than
       * requested") even though the write itself succeeded. */
      if (error && *error &&
          (g_error_matches (*error, G_USB_DEVICE_ERROR, G_USB_DEVICE_ERROR_INTERNAL) ||
           strstr ((*error)->message, "more data than requested") != NULL))
        {
          fp_dbg ("ignoring overflow on OUT transfer (%s)", (*error)->message);
          g_clear_error (error);
          return TRUE;
        }
      return FALSE;
    }

  return TRUE;
}

static gboolean
et577_usb_read (FpDeviceEt577 *self, guint8 *data, gsize len,
                GCancellable *cancellable, GError **error)
{
  gsize actual = 0;
  GUsbDevice *usb = fpi_device_get_usb_device (FP_DEVICE (self));

  if (!g_usb_device_bulk_transfer (usb, ET577_EPIN, data, len, &actual,
                                   ET577_TIMEOUT, cancellable, error))
    {
      if (error && *error &&
          (g_error_matches (*error, G_USB_DEVICE_ERROR, G_USB_DEVICE_ERROR_INTERNAL) ||
           strstr ((*error)->message, "more data than requested") != NULL))
        {
          fp_dbg ("ignoring overflow on IN transfer (requested %" G_GSIZE_FORMAT "): %s",
                 len, (*error)->message);
          g_clear_error (error);
          return TRUE;
        }
      return FALSE;
    }

  if (actual != len)
    {
      /* Command responses do not always have the same length as the
       * command (e.g. "62 67 03" answers with 10 bytes). Callers that
       * care about the exact size check it themselves. */
      fp_dbg ("short USB read: got %" G_GSIZE_FORMAT " of %" G_GSIZE_FORMAT " bytes",
              actual, len);
    }

  return TRUE;
}

/* Send a command and consume its response (response length == command length). */
static gboolean
et577_command (FpDeviceEt577 *self, const guint8 *data, gsize len,
               GCancellable *cancellable, GError **error)
{
  guint8 resp[64];

  if (!et577_usb_write (self, data, len, cancellable, error))
    return FALSE;

  fp_dbg ("cmd %02x %02x %02x (len %zu) sent", data[4], data[5], data[6], len);

  /* Read any response. Response lengths vary per command (7, 9, 10, 13, 18),
   * so use a buffer large enough for the largest one. */
  if (!et577_usb_read (self, resp, sizeof (resp), cancellable, error))
    return FALSE;

  if (resp[0] != 0x53 /* 'S' */ || resp[1] != 0x49 || resp[2] != 0x47 || resp[3] != 0x45)
    {
      g_warning ("et577: invalid device response: %02x %02x %02x %02x",
                 resp[0], resp[1], resp[2], resp[3]);
      g_set_error (error, G_USB_DEVICE_ERROR, G_USB_DEVICE_ERROR_IO,
                   "invalid device response: %02x %02x %02x %02x",
                   resp[0], resp[1], resp[2], resp[3]);
      return FALSE;
    }

  return TRUE;
}

static gboolean
et577_init_device (FpDeviceEt577 *self, GCancellable *cancellable, GError **error)
{
  gsize i;

  if (self->initialized)
    return TRUE;

  for (i = 0; i < ET577_INIT1_COUNT; i++)
    if (!et577_command (self, et577_init1[i].data, et577_init1[i].len,
                        cancellable, error))
      return FALSE;

  /* Calibration: trigger, then the 3990-byte calibration blob; the 7-byte
   * response arrives only after the calibration data has been written. */
  if (!et577_usb_write (self, et577_calib_cmd, sizeof (et577_calib_cmd),
                        cancellable, error))
    return FALSE;
  if (!et577_usb_write (self, et577_calib_data, sizeof (et577_calib_data),
                        cancellable, error))
    return FALSE;
  {
    guint8 resp[8];
    if (!et577_usb_read (self, resp, 7, cancellable, error))
      return FALSE;
  }

  for (i = 0; i < ET577_INIT2_COUNT; i++)
    if (!et577_command (self, et577_init2[i].data, et577_init2[i].len,
                        cancellable, error))
      return FALSE;

  /* Windows captures one image immediately after init2 and then sends the
   * stop sequence, which puts the sensor into finger-poll mode. */
  {
    guint8 tmp[ET577_IMGSIZE];
    gdouble std;

    if (!et577_usb_write (self, et577_image_cmd, sizeof (et577_image_cmd),
                          cancellable, error))
      return FALSE;
    if (!et577_usb_read (self, tmp, ET577_IMGSIZE, cancellable, error))
      return FALSE;

    std = et577_image_std (tmp);
    self->init_had_finger = (std >= ET577_PRESS_STD);
    fp_dbg ("init image std=%.1f (finger=%d)", std, self->init_had_finger);
  }

  for (i = 0; i < ET577_STOP_BURST_COUNT; i++)
    if (!et577_command (self, et577_stop_burst[i].data, et577_stop_burst[i].len,
                        cancellable, error))
      return FALSE;

  self->initialized = TRUE;
  return TRUE;
}

/* Poll the sensor for finger presence.  This does not capture an image. */
static gboolean
et577_poll_finger (FpDeviceEt577 *self, gboolean *present,
                   GCancellable *cancellable, GError **error)
{
  guint8 resp[64];

  if (!et577_usb_write (self, et577_poll_cmd, sizeof (et577_poll_cmd),
                        cancellable, error))
    return FALSE;

  if (!et577_usb_read (self, resp, sizeof (resp), cancellable, error))
    return FALSE;

  if (resp[0] != 0x53 || resp[1] != 0x49 || resp[2] != 0x47 || resp[3] != 0x45)
    {
      g_set_error (error, G_USB_DEVICE_ERROR, G_USB_DEVICE_ERROR_IO,
                   "invalid poll response: %02x %02x %02x %02x %02x %02x %02x",
                   resp[0], resp[1], resp[2], resp[3], resp[4], resp[5], resp[6]);
      return FALSE;
    }

  *present = (resp[5] == ET577_POLL_FINGER_PRESENT);
  return TRUE;
}

/* Capture a short burst (start sequence, 3 images, stop sequence). */
static gboolean
et577_capture_burst (FpDeviceEt577 *self, guint8 *image,
                     GCancellable *cancellable, GError **error)
{
  guint8 tmp[ET577_IMGSIZE];
  gdouble best_std = -1.0;
  gsize i;
  gint k;

  for (i = 0; i < ET577_START_BURST_COUNT; i++)
    if (!et577_command (self, et577_start_burst[i].data,
                        et577_start_burst[i].len, cancellable, error))
      return FALSE;

  for (k = 0; k < 3; k++)
    {
      gdouble std;

      if (k > 0)
        for (i = 0; i < ET577_REPEAT_COUNT; i++)
          if (!et577_command (self, et577_repeat[i].data,
                              et577_repeat[i].len, cancellable, error))
            return FALSE;

      if (!et577_usb_write (self, et577_image_cmd, sizeof (et577_image_cmd),
                            cancellable, error))
        return FALSE;
      if (!et577_usb_read (self, tmp, ET577_IMGSIZE, cancellable, error))
        return FALSE;

      std = et577_image_std (tmp);
      fp_dbg ("burst image %d std=%.1f", k, std);
      memcpy (self->burst_images[k], tmp, ET577_IMGSIZE);
      if (std > best_std)
        {
          best_std = std;
          memcpy (image, tmp, ET577_IMGSIZE);
        }
    }

  self->burst_count = 3;

  for (i = 0; i < ET577_STOP_BURST_COUNT; i++)
    if (!et577_command (self, et577_stop_burst[i].data,
                        et577_stop_burst[i].len, cancellable, error))
      return FALSE;

  self->captured_std = best_std;
  return TRUE;
}

static gdouble
et577_image_std (const guint8 *image)
{
  gdouble mean = 0.0, var = 0.0;
  gint i;

  for (i = 0; i < ET577_IMGSIZE; i++)
    mean += image[i];
  mean /= ET577_IMGSIZE;

  for (i = 0; i < ET577_IMGSIZE; i++)
    var += (image[i] - mean) * (image[i] - mean);
  var /= ET577_IMGSIZE;

  return sqrt (var);
}

/* Wait for the finger, then capture a short burst.  The sensor always gets
 * re-initialised before this is called; the sacrificial image taken during
 * initialisation tells us whether the finger is still resting on the sensor.
 * The presence poll is only trusted right after an initialisation, because
 * it latches to "present" after an image burst. */
static gboolean
et577_wait_for_press (FpDeviceEt577 *self, guint8 *image,
                      GCancellable *cancellable, GError **error)
{
  gboolean present = FALSE;
  gint64 deadline = g_get_monotonic_time () + 20 * G_TIME_SPAN_SECOND;
  gint present_streak = 0;
  guint count = 0;

  if (self->init_had_finger)
    {
      self->initialized = FALSE;
      g_warning ("et577: finger still on sensor, please lift it");
      g_set_error_literal (error, FP_DEVICE_RETRY,
                           FP_DEVICE_RETRY_REMOVE_FINGER,
                           "Please remove the finger and try again");
      return FALSE;
    }

  g_warning ("et577: ready for press");

  /* Wait for a confirmed press. */
  for (;;)
    {
      if (g_cancellable_is_cancelled (cancellable))
        {
          g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_CANCELLED,
                               "Operation cancelled");
          return FALSE;
        }
      if (g_get_monotonic_time () > deadline)
        {
          self->initialized = FALSE;
          g_set_error_literal (error, FP_DEVICE_RETRY,
                               FP_DEVICE_RETRY_REMOVE_FINGER,
                               "Timed out waiting for a finger");
          return FALSE;
        }

      if (!et577_poll_finger (self, &present, cancellable, error))
        return FALSE;

      if (present)
        {
          if (++present_streak >= 3)
            break;
        }
      else
        {
          present_streak = 0;
        }

      if (count++ % 100 == 0)
        g_warning ("et577: polling for finger...");
      g_usleep (30 * 1000);
    }

  g_warning ("et577: FINGER detected, capturing burst");
  if (!et577_capture_burst (self, image, cancellable, error))
    return FALSE;

  g_warning ("et577: burst captured, best std=%.1f", self->captured_std);
  return TRUE;
}

/* ------------------------------------------------------------------ */
/* Host-side matcher: rotation + translation normalized correlation     */
/* ------------------------------------------------------------------ */

/* Extract normalized 24x24 patches from an image.  Returns the number of
 * patches written to @out (each ET577_PATCH_DIM floats, unit norm). */
static gint
et577_extract_patches (const guint8 *img, float *out, gint *xs, gint *ys)
{
  gint n = 0;
  gint x, y;

  for (y = 0; y + ET577_PATCH <= ET577_HEIGHT; y += ET577_PATCH_STRIDE)
    {
      for (x = 0; x + ET577_PATCH <= ET577_WIDTH; x += ET577_PATCH_STRIDE)
        {
          float *p = out + (gsize) n * ET577_PATCH_DIM;
          gdouble mean = 0.0, norm = 0.0;
          gint i, j;

          for (j = 0; j < ET577_PATCH; j++)
            for (i = 0; i < ET577_PATCH; i++)
              mean += img[(y + j) * ET577_WIDTH + (x + i)];
          mean /= ET577_PATCH_DIM;

          for (j = 0; j < ET577_PATCH; j++)
            for (i = 0; i < ET577_PATCH; i++)
              {
                gdouble d = img[(y + j) * ET577_WIDTH + (x + i)] - mean;
                norm += d * d;
              }
          norm = sqrt (norm);

          if (sqrt (norm * norm / ET577_PATCH_DIM) < ET577_PATCH_MIN_STD)
            continue;

          for (j = 0; j < ET577_PATCH; j++)
            for (i = 0; i < ET577_PATCH; i++)
              p[j * ET577_PATCH + i] =
                (img[(y + j) * ET577_WIDTH + (x + i)] - mean) / norm;

          if (xs) xs[n] = x;
          if (ys) ys[n] = y;

          if (++n >= ET577_PATCH_MAX)
            return n;
        }
    }

  return n;
}

/* Rotate a raw 8-bit image by @deg degrees (bilinear, edge clamp). */
static void
et577_rotate_u8 (const guint8 *in, gdouble deg, guint8 *out)
{
  const gdouble cx = (ET577_WIDTH - 1) / 2.0;
  const gdouble cy = (ET577_HEIGHT - 1) / 2.0;
  const gdouble rad = deg * G_PI / 180.0;
  const gdouble c = cos (rad);
  const gdouble s = sin (rad);
  gint x, y;

  for (y = 0; y < ET577_HEIGHT; y++)
    {
      for (x = 0; x < ET577_WIDTH; x++)
        {
          gdouble dx = x - cx;
          gdouble dy = y - cy;
          gdouble sx = cx + dx * c + dy * s;
          gdouble sy = cy - dx * s + dy * c;
          gint x0 = (gint) floor (sx);
          gint y0 = (gint) floor (sy);
          gdouble fx, fy;

          if (x0 < 0) x0 = 0;
          if (y0 < 0) y0 = 0;
          if (x0 > ET577_WIDTH - 2) x0 = ET577_WIDTH - 2;
          if (y0 > ET577_HEIGHT - 2) y0 = ET577_HEIGHT - 2;
          fx = CLAMP (sx - x0, 0.0, 1.0);
          fy = CLAMP (sy - y0, 0.0, 1.0);

          out[y * ET577_WIDTH + x] =
            (guint8) ((1 - fy) * ((1 - fx) * in[y0 * ET577_WIDTH + x0] +
                                  fx * in[y0 * ET577_WIDTH + x0 + 1]) +
                      fy * ((1 - fx) * in[(y0 + 1) * ET577_WIDTH + x0] +
                            fx * in[(y0 + 1) * ET577_WIDTH + x0 + 1]));
        }
    }
}

/* Patch-based similarity: a small sensor only observes a partial fingerprint,
 * so compare local patches instead of the whole image.  Require several
 * consistent patch matches to avoid random correlations. */
static gdouble
et577_patch_similarity (const guint8 *a, const guint8 *b, gint *out_raw)
{
  float *pa = g_malloc (ET577_PATCH_MAX * ET577_PATCH_DIM * sizeof (float));
  float *pb = g_malloc (ET577_PATCH_MAX * ET577_PATCH_DIM * sizeof (float));
  gint *ax = g_malloc (ET577_PATCH_MAX * sizeof (gint));
  gint *ay = g_malloc (ET577_PATCH_MAX * sizeof (gint));
  gint *bx = g_malloc (ET577_PATCH_MAX * sizeof (gint));
  gint *by = g_malloc (ET577_PATCH_MAX * sizeof (gint));
  guint8 rot[ET577_IMGSIZE];
  gint nb;
  gdouble best = 0.0;
  gint best_raw = 0;
  gdouble angle;
  gint binx = ET577_WIDTH / ET577_PATCH_STRIDE + 1;
  gint biny = ET577_HEIGHT / ET577_PATCH_STRIDE + 1;

  nb = et577_extract_patches (b, pb, bx, by);

  for (angle = -ET577_ANGLE_RANGE; angle <= ET577_ANGLE_RANGE + 0.01;
       angle += ET577_ANGLE_STEP)
    {
      static gint bins[2 * 20 + 1][2 * 18 + 1];
      gint na, i, j, k;
      gint raw = 0, binmax = 0;

      memset (bins, 0, sizeof (bins));

      if (angle == 0.0)
        na = et577_extract_patches (a, pa, ax, ay);
      else
        {
          et577_rotate_u8 (a, angle, rot);
          na = et577_extract_patches (rot, pa, ax, ay);
        }

      for (i = 0; i < na; i++)
        {
          const float *va = pa + (gsize) i * ET577_PATCH_DIM;
          gint bestj = -1;
          float bestdot = 0.0f;

          for (j = 0; j < nb; j++)
            {
              const float *vb = pb + (gsize) j * ET577_PATCH_DIM;
              float dot = 0.0f;

              for (k = 0; k < ET577_PATCH_DIM; k++)
                dot += va[k] * vb[k];

              if (dot >= ET577_PATCH_GOOD)
                {
                  raw++;
                  if (dot > bestdot)
                    {
                      bestdot = dot;
                      bestj = j;
                    }
                }
            }

          if (bestj >= 0)
            {
              gint dx = (bx[bestj] - ax[i]) / ET577_PATCH_STRIDE;
              gint dy = (by[bestj] - ay[i]) / ET577_PATCH_STRIDE;

              if (dx >= -20 && dx <= 20 && dy >= -18 && dy <= 18)
                {
                  bins[dx + 20][dy + 18]++;
                  if (bins[dx + 20][dy + 18] > binmax)
                    binmax = bins[dx + 20][dy + 18];
                }
            }
        }

      if (binmax > best)
        {
          best = binmax;
          best_raw = raw;
        }
    }

  g_free (pa);
  g_free (pb);
  g_free (ax);
  g_free (ay);
  g_free (bx);
  g_free (by);

  if (out_raw)
    *out_raw = best_raw;

  (void) binx;
  (void) biny;

  return best;
}

/* ------------------------------------------------------------------ */
/* Template (de)serialization                                          */
/* ------------------------------------------------------------------ */

static void
et577_template_header (GByteArray *arr, guint count)
{
  guint8 hdr[12];
  hdr[0] = ET577_TEMPLATE_MAGIC0;
  hdr[1] = ET577_TEMPLATE_MAGIC1;
  hdr[2] = ET577_TEMPLATE_MAGIC2;
  hdr[3] = ET577_TEMPLATE_MAGIC3;
  hdr[4] = ET577_TEMPLATE_VERSION;
  hdr[5] = count & 0xff;
  hdr[6] = (ET577_WIDTH >> 8) & 0xff;
  hdr[7] = ET577_WIDTH & 0xff;
  hdr[8] = (ET577_HEIGHT >> 8) & 0xff;
  hdr[9] = ET577_HEIGHT & 0xff;
  hdr[10] = 0;
  hdr[11] = 0;
  g_byte_array_append (arr, hdr, sizeof (hdr));
}

static GVariant *
et577_images_to_variant (GPtrArray *images)
{
  GByteArray *arr = g_byte_array_new ();
  GBytes *bytes;
  GVariant *variant;
  guint i;

  et577_template_header (arr, images->len);
  for (i = 0; i < images->len; i++)
    g_byte_array_append (arr, g_ptr_array_index (images, i), ET577_IMGSIZE);

  bytes = g_byte_array_free_to_bytes (arr);
  variant = g_variant_new_from_bytes (G_VARIANT_TYPE ("ay"), bytes, TRUE);
  g_bytes_unref (bytes);
  return variant;
}

/* Returns a newly allocated GPtrArray of guint8* images, or NULL. */
static GPtrArray *
et577_variant_to_images (GVariant *variant)
{
  const guint8 *data;
  gsize len, i;
  guint count;
  GPtrArray *images;

  if (variant == NULL)
    return NULL;

  if (!g_variant_is_of_type (variant, G_VARIANT_TYPE ("ay")))
    return NULL;

  data = g_variant_get_fixed_array (variant, &len, 1);
  if (len < 12)
    return NULL;

  if (data[0] != ET577_TEMPLATE_MAGIC0 || data[1] != ET577_TEMPLATE_MAGIC1 ||
      data[2] != ET577_TEMPLATE_MAGIC2 || data[3] != ET577_TEMPLATE_MAGIC3)
    return NULL;

  if (data[4] != ET577_TEMPLATE_VERSION)
    return NULL;

  count = data[5];
  if (count == 0 || count > ET577_MAX_TEMPLATES)
    return NULL;

  if (len != 12 + (gsize) count * ET577_IMGSIZE)
    return NULL;

  images = g_ptr_array_new_with_free_func (g_free);
  for (i = 0; i < count; i++)
    g_ptr_array_add (images, g_memdup2 (data + 12 + i * ET577_IMGSIZE, ET577_IMGSIZE));

  return images;
}

/* Compare one captured image against a template blob. */
static gdouble
et577_match_template (const guint8 *captured, GVariant *variant, gint *best_index,
                     gint *best_raw)
{
  g_autoptr(GPtrArray) images = et577_variant_to_images (variant);
  gdouble best = 0.0;
  gint raw_best = 0;
  guint i;

  if (images == NULL)
    {
      if (best_raw) *best_raw = 0;
      return 0.0;
    }

  for (i = 0; i < images->len; i++)
    {
      gint raw = 0;
      gdouble score = et577_patch_similarity (captured,
                                              g_ptr_array_index (images, i),
                                              &raw);
      if (score > best)
        {
          best = score;
          raw_best = raw;
          if (best_index)
            *best_index = i;
        }
    }

  if (best_raw)
    *best_raw = raw_best;

  return best;
}

/* ------------------------------------------------------------------ */
/* Actions                                                             */
/* ------------------------------------------------------------------ */

typedef enum {
  ET577_OP_ENROLL,
  ET577_OP_VERIFY,
  ET577_OP_IDENTIFY,
} Et577Op;

typedef struct
{
  Et577Op op;
  FpPrint *print;
  GPtrArray *prints;
} Et577TaskData;

static void et577_start_task (FpDevice *dev, Et577Op op, FpPrint *print,
                              GPtrArray *prints, GAsyncReadyCallback callback);
static void et577_enroll_done (GObject *source, GAsyncResult *result, gpointer user_data);

static void
et577_task_data_free (gpointer data)
{
  Et577TaskData *td = data;
  g_clear_object (&td->print);
  g_clear_pointer (&td->prints, g_ptr_array_unref);
  g_free (td);
}

static void
et577_worker (GTask *task, gpointer source, gpointer task_data,
              GCancellable *cancellable)
{
  FpDeviceEt577 *self = source;
  GError *error = NULL;
  guint8 image[ET577_IMGSIZE];

  g_mutex_lock (&self->io_lock);
  self->worker_running = TRUE;

  if (!et577_init_device (self, cancellable, &error) ||
      !et577_wait_for_press (self, image, cancellable, &error))
    {
      self->initialized = FALSE;
      self->worker_running = FALSE;
      g_cond_broadcast (&self->io_cond);
      g_mutex_unlock (&self->io_lock);
      g_task_return_error (task, error);
      return;
    }

  memcpy (self->captured, image, ET577_IMGSIZE);

  self->worker_running = FALSE;
  g_cond_broadcast (&self->io_cond);
  g_mutex_unlock (&self->io_lock);
  g_task_return_boolean (task, TRUE);
}

static gboolean
et577_retry_enroll_cb (gpointer data)
{
  FpDevice *dev = data;

  et577_start_task (dev, ET577_OP_ENROLL, NULL, NULL, et577_enroll_done);
  return G_SOURCE_REMOVE;
}

static void
et577_enroll_done (GObject *source, GAsyncResult *result, gpointer user_data)
{
  FpDevice *dev = FP_DEVICE (source);
  FpDeviceEt577 *self = FPI_DEVICE_ET577 (dev);
  g_clear_handle_id (&self->watchdog_id, g_source_remove);
  g_autoptr(GError) error = NULL;

  if (!g_task_propagate_boolean (G_TASK (result), &error))
    {
      if (error && error->domain == FP_DEVICE_RETRY)
        {
          /* Report the retry and keep the current enrollment stage. */
          fpi_device_enroll_progress (dev, self->enroll_stages_passed, NULL,
                                      g_steal_pointer (&error));
          self->initialized = FALSE;
          g_timeout_add_seconds_full (G_PRIORITY_DEFAULT, 2,
                                      et577_retry_enroll_cb,
                                      g_object_ref (dev), g_object_unref);
          return;
        }

      self->enroll_stages_passed = 0;
      g_clear_pointer (&self->enroll_images, g_byte_array_unref);
      fpi_device_enroll_complete (dev, NULL, g_steal_pointer (&error));
      return;
    }

  if (self->enroll_images == NULL)
    self->enroll_images = g_byte_array_new ();

  {
    guint b;
    for (b = 0; b < self->burst_count; b++)
      g_byte_array_append (self->enroll_images, self->burst_images[b], ET577_IMGSIZE);
  }
  self->enroll_stages_passed++;

  fpi_device_enroll_progress (dev, self->enroll_stages_passed, NULL, NULL);

  if (self->enroll_stages_passed >= ET577_ENROLL_STAGES)
    {
      GPtrArray *images = g_ptr_array_new_with_free_func (g_free);
      guint i, total;
      GVariant *data;
      FpPrint *print = NULL;

      total = self->enroll_images->len / ET577_IMGSIZE;
      if (total > ET577_MAX_TEMPLATES)
        total = ET577_MAX_TEMPLATES;
      g_warning ("et577: storing %u template images", total);

      for (i = 0; i < total; i++)
        g_ptr_array_add (images,
                         g_memdup2 (self->enroll_images->data + i * ET577_IMGSIZE,
                                    ET577_IMGSIZE));

      fpi_device_get_enroll_data (dev, &print);
      fpi_print_set_type (print, FPI_PRINT_RAW);

      if (total == 0)
        {
          g_ptr_array_unref (images);
          fpi_device_enroll_complete (dev, NULL,
                                      fpi_device_error_new_msg (FP_DEVICE_ERROR_GENERAL,
                                                                "No templates captured"));
          self->enroll_stages_passed = 0;
          g_clear_pointer (&self->enroll_images, g_byte_array_unref);
          return;
        }

      data = et577_images_to_variant (images);
      g_ptr_array_unref (images);

      /* @data is a floating reference; g_object_set() consumes it. */
      g_object_set (print, "fpi-data", data, NULL);

      fpi_device_enroll_complete (dev, g_object_ref (print), NULL);

      self->enroll_stages_passed = 0;
      g_clear_pointer (&self->enroll_images, g_byte_array_unref);
    }
  else
    {
      FpDeviceClass *cls = FP_DEVICE_GET_CLASS (dev);

      /* The poll state latches to "finger present" after an image burst.
       * Re-initialising the sensor resets it, so do that before the next
       * enrollment stage. */
      self->initialized = FALSE;
      g_timeout_add_full (G_PRIORITY_DEFAULT, 1500,
                          et577_retry_enroll_cb, g_object_ref (dev),
                          g_object_unref);
      (void) cls;
    }
}

static void
et577_verify_done (GObject *source, GAsyncResult *result, gpointer user_data)
{
  FpDevice *dev = FP_DEVICE (source);
  FpDeviceEt577 *self = FPI_DEVICE_ET577 (dev);
  g_clear_handle_id (&self->watchdog_id, g_source_remove);
  Et577TaskData *td = user_data;
  g_autoptr(GError) error = NULL;
  FpPrint *print = NULL;
  gint score = 0;
  gboolean matched = FALSE;
  g_autoptr(GVariant) variant = NULL;

  if (!g_task_propagate_boolean (G_TASK (result), &error))
    {
      if (error && error->domain == FP_DEVICE_RETRY)
        {
          self->initialized = FALSE;
          fpi_device_verify_report (dev, FPI_MATCH_ERROR, NULL,
                                    g_steal_pointer (&error));
          fpi_device_verify_complete (dev, NULL);
        }
      else
        {
          fpi_device_verify_complete (dev, g_steal_pointer (&error));
        }
      return;
    }

  fpi_device_get_verify_data (dev, &print);
  if (print == NULL && td != NULL)
    print = td->print;
  g_object_get (print, "fpi-data", &variant, NULL);

  if (variant != NULL)
    {
      gint best_index = 0;
      gdouble best = 0.0;
      guint b;

      gint raw_best = 0;

      for (b = 0; b < MAX (self->burst_count, 1); b++)
        {
          gint idx = 0, raw = 0;
          gdouble s = et577_match_template (self->burst_images[b], variant, &idx, &raw);
          if (s > best)
            {
              best = s;
              best_index = idx;
              raw_best = raw;
            }
        }

      score = (gint) best;
      matched = best >= ET577_MATCH_THRESHOLD && raw_best >= ET577_RAW_MIN;
      g_warning ("et577: verify best template %d, consensus %d raw %d (need %d/%d), %s",
                 best_index, score, raw_best, (gint) ET577_MATCH_THRESHOLD,
                 (gint) ET577_RAW_MIN, matched ? "MATCH" : "NO MATCH");
    }
  else
    {
      fp_warn ("verify: enrolled print has no template data");
    }

  self->match_score = score;

  fpi_device_verify_report (dev,
                            matched ? FPI_MATCH_SUCCESS : FPI_MATCH_FAIL,
                            NULL, NULL);
  fpi_device_verify_complete (dev, NULL);
}

static void
et577_identify_done (GObject *source, GAsyncResult *result, gpointer user_data)
{
  FpDevice *dev = FP_DEVICE (source);
  FpDeviceEt577 *self = FPI_DEVICE_ET577 (dev);
  g_clear_handle_id (&self->watchdog_id, g_source_remove);
  Et577TaskData *td = user_data;
  g_autoptr(GError) error = NULL;
  gdouble best = 0.0;
  gint raw_best = 0;
  FpPrint *best_print = NULL;
  guint i;

  if (!g_task_propagate_boolean (G_TASK (result), &error))
    {
      if (error && error->domain == FP_DEVICE_RETRY)
        {
          self->initialized = FALSE;
          fpi_device_identify_report (dev, NULL, NULL, g_steal_pointer (&error));
          fpi_device_identify_complete (dev, NULL);
        }
      else
        {
          fpi_device_identify_complete (dev, g_steal_pointer (&error));
        }
      return;
    }

  for (i = 0; i < td->prints->len; i++)
    {
      FpPrint *print = g_ptr_array_index (td->prints, i);
      g_autoptr(GVariant) variant = NULL;
      gdouble score;
      gint raw_score = 0;

      g_object_get (print, "fpi-data", &variant, NULL);
      score = 0.0;
      {
        guint b;
        for (b = 0; b < MAX (self->burst_count, 1); b++)
          {
            gint raw = 0;
            gdouble s = et577_match_template (self->burst_images[b], variant, NULL, &raw);
            if (s > score)
              {
                score = s;
                raw_score = raw;
              }
          }
      }
      g_warning ("et577: identify print %u consensus %d raw %d", i, (gint) score, raw_score);

      if (score > best)
        {
          best = score;
          raw_best = raw_score;
          best_print = print;
        }
    }

  self->match_score = (gint) best;

  if (best >= ET577_MATCH_THRESHOLD && raw_best >= ET577_RAW_MIN)
    {
      fpi_device_identify_report (dev, best_print, NULL, NULL);
      fpi_device_identify_complete (dev, NULL);
    }
  else
    {
      fpi_device_identify_report (dev, NULL, NULL, NULL);
      fpi_device_identify_complete (dev, NULL);
    }
}

static gboolean
et577_watchdog_cb (gpointer data)
{
  FpDeviceEt577 *self = FPI_DEVICE_ET577 (data);

  self->watchdog_id = 0;
  g_warning ("et577: watchdog fired, cancelling operation");
  if (self->cancellable)
    g_cancellable_cancel (self->cancellable);

  return G_SOURCE_REMOVE;
}

static void
et577_start_task (FpDevice *dev, Et577Op op, FpPrint *print, GPtrArray *prints,
                  GAsyncReadyCallback callback)
{
  FpDeviceEt577 *self = FPI_DEVICE_ET577 (dev);
  Et577TaskData *td = g_new0 (Et577TaskData, 1);
  GTask *task;

  td->op = op;
  td->print = print ? g_object_ref (print) : NULL;
  td->prints = prints ? g_ptr_array_ref (prints) : NULL;

  g_clear_object (&self->cancellable);
  self->cancellable = g_object_ref (fpi_device_get_cancellable (dev));

  task = g_task_new (dev, self->cancellable, callback, td);
  g_task_set_task_data (task, td, et577_task_data_free);
  g_task_run_in_thread (task, et577_worker);
  g_object_unref (task);

  g_clear_handle_id (&self->watchdog_id, g_source_remove);
  self->watchdog_id = g_timeout_add_seconds_full (G_PRIORITY_DEFAULT, 25,
                                                  et577_watchdog_cb,
                                                  g_object_ref (dev),
                                                  g_object_unref);
}

static void
dev_enroll (FpDevice *dev)
{
  et577_start_task (dev, ET577_OP_ENROLL, NULL, NULL, et577_enroll_done);
}

static void
dev_verify (FpDevice *dev)
{
  FpPrint *print = NULL;

  fpi_device_get_verify_data (dev, &print);
  et577_start_task (dev, ET577_OP_VERIFY, print, NULL, et577_verify_done);
}

static void
dev_identify (FpDevice *dev)
{
  GPtrArray *prints = NULL;

  fpi_device_get_identify_data (dev, &prints);
  et577_start_task (dev, ET577_OP_IDENTIFY, NULL, prints, et577_identify_done);
}

static void
dev_cancel (FpDevice *dev)
{
  FpDeviceEt577 *self = FPI_DEVICE_ET577 (dev);

  if (self->cancellable)
    g_cancellable_cancel (self->cancellable);
}

/* ------------------------------------------------------------------ */
/* Opening / closing                                                   */
/* ------------------------------------------------------------------ */

static void
dev_open (FpDevice *dev)
{
  FpDeviceEt577 *self = FPI_DEVICE_ET577 (dev);
  GError *error = NULL;
  GUsbDevice *usb = fpi_device_get_usb_device (dev);

  g_usb_device_claim_interface (usb, 0, 0, &error);

  self->initialized = FALSE;

  fpi_device_open_complete (dev, error);
}

static void
dev_close (FpDevice *dev)
{
  FpDeviceEt577 *self = FPI_DEVICE_ET577 (dev);
  GError *error = NULL;

  g_clear_handle_id (&self->watchdog_id, g_source_remove);
  if (self->cancellable)
    g_cancellable_cancel (self->cancellable);

  g_mutex_lock (&self->io_lock);
  if (self->worker_running)
    g_cond_wait_until (&self->io_cond, &self->io_lock,
                       g_get_monotonic_time () + 3 * G_TIME_SPAN_SECOND);
  g_mutex_unlock (&self->io_lock);

  g_clear_object (&self->cancellable);

  g_usb_device_release_interface (fpi_device_get_usb_device (dev), 0, 0, &error);

  self->initialized = FALSE;

  fpi_device_close_complete (dev, error);
}

/* ------------------------------------------------------------------ */
/* Driver registration                                                 */
/* ------------------------------------------------------------------ */

static const FpIdEntry id_table[] = {
  { .vid = ET577_VID, .pid = ET577_PID },
  { .vid = 0, .pid = 0 },
};

static void
fpi_device_et577_finalize (GObject *object)
{
  FpDeviceEt577 *self = FPI_DEVICE_ET577 (object);

  g_clear_handle_id (&self->watchdog_id, g_source_remove);
  g_clear_pointer (&self->enroll_images, g_byte_array_unref);
  g_clear_object (&self->cancellable);
  g_cond_clear (&self->io_cond);
  g_mutex_clear (&self->io_lock);

  G_OBJECT_CLASS (fpi_device_et577_parent_class)->finalize (object);
}

static void
fpi_device_et577_init (FpDeviceEt577 *self)
{
  g_mutex_init (&self->io_lock);
  g_cond_init (&self->io_cond);
}

static void
fpi_device_et577_class_init (FpDeviceEt577Class *klass)
{
  FpDeviceClass *dev_class = FP_DEVICE_CLASS (klass);
  GObjectClass *object_class = G_OBJECT_CLASS (klass);

  object_class->finalize = fpi_device_et577_finalize;

  dev_class->id = "et577";
  dev_class->full_name = "Egis Technology Inc. EH577 (ET300)";
  dev_class->type = FP_DEVICE_TYPE_USB;
  dev_class->id_table = id_table;
  dev_class->scan_type = FP_SCAN_TYPE_PRESS;
  dev_class->nr_enroll_stages = ET577_ENROLL_STAGES;

  dev_class->open = dev_open;
  dev_class->close = dev_close;
  dev_class->enroll = dev_enroll;
  dev_class->verify = dev_verify;
  dev_class->identify = dev_identify;
  dev_class->cancel = dev_cancel;

  fpi_device_class_auto_initialize_features (dev_class);
}
