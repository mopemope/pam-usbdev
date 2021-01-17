# pam-usbdev

PAM module for authentication with USB Devices.

## Configuration
Create a file named `.authorized_device` in your home directory. Configure as follows:

```
# your device name
[xxxxx]
# device vendor id
vendor_id = 0x1530
# device product id
product_id = 0x0080
```

Install and configure pam-usbdev as you would any other PAM module.
