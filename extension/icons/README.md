# Extension Icons

This directory should contain the following icon files:

- icon-16.png (16x16 pixels)
- icon-32.png (32x32 pixels)
- icon-48.png (48x48 pixels)
- icon-128.png (128x128 pixels)

## Creating Icons

You can create these icons from the Soul Password Manager logo:

1. Use the existing icons from `public/icons/` directory
2. Resize them to the required dimensions
3. Save them in this directory

## Quick Setup

Copy the PWA icons as placeholders:

```bash
cp ../public/icons/pwa-192x192.png icon-128.png
# Then resize icon-128.png to create smaller versions
```

Or use an online tool like:
- https://realfavicongenerator.net/
- https://www.favicon-generator.org/

## Required Sizes

- **16x16**: Browser toolbar icon (default size)
- **32x32**: Retina display toolbar icon
- **48x48**: Extension management page
- **128x128**: Chrome Web Store listing
