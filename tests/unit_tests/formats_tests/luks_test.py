import unittest
from unittest.mock import Mock, patch

from blivet.formats.luks import LUKS
from blivet.size import Size
from blivet.static_data import encryption_data
from blivet import blockdev
from blivet.devicelibs import crypto as crypto_lib
from blivet.errors import LUKSError, FormatDestroyError
from blivet.formats import DeviceFormat
from blivet.tasks import availability


class LUKSNodevTestCase(unittest.TestCase):
    def setUp(self):
        encryption_data.pbkdf_args = None

    def test_create_discard_option(self):
        # flags.discard_new=False --> no discard
        fmt = LUKS(exists=False)
        self.assertEqual(fmt.options, None)

        fmt = LUKS(exists=True)
        self.assertEqual(fmt.options, None)

        fmt = LUKS(passphrase="passphrase")
        with patch("blivet.devicelibs.crypto.calculate_luks2_max_memory", return_value=None):
            with patch("blivet.devicelibs.crypto.get_optimal_luks_sector_size", return_value=0):
                with patch("blivet.formats.luks.blockdev") as bd:
                    fmt._create()
                    bd.crypto.luks_format.assert_called()
                    fmt._post_create()
                    bd.crypto.luks_set_persistent_flags.assert_not_called()

        # flags.discard_new=True --> discard if creating new
        with patch("blivet.formats.luks.flags.discard_new", True):
            fmt = LUKS(exists=True)
            self.assertEqual(fmt.options, None)

            fmt = LUKS(exists=False)
            self.assertEqual(fmt.options, "discard")

            # do not add if already there
            fmt = LUKS(exists=False, options="discard")
            self.assertEqual(fmt.options, "discard")

            # add with comma after other option(s)
            fmt = LUKS(exists=False, options="blah")
            self.assertEqual(fmt.options, "blah,discard")

            fmt = LUKS(passphrase="passphrase")
            with patch("blivet.devicelibs.crypto.calculate_luks2_max_memory", return_value=None):
                with patch("blivet.devicelibs.crypto.get_optimal_luks_sector_size", return_value=0):
                    with patch("blivet.formats.luks.blockdev") as bd:
                        fmt._create()
                        bd.crypto.luks_format.assert_called()
                        fmt._post_create()
                        bd.crypto.luks_set_persistent_flags.assert_called()

            # LUKS 1 doesn't support the persistent flags
            fmt = LUKS(passphrase="passphrase", luks_version="luks1")
            with patch("blivet.devicelibs.crypto.calculate_luks2_max_memory", return_value=None):
                with patch("blivet.devicelibs.crypto.get_optimal_luks_sector_size", return_value=0):
                    with patch("blivet.formats.luks.blockdev") as bd:
                        fmt._create()
                        bd.crypto.luks_format.assert_called()
                        fmt._post_create()
                        bd.crypto.luks_set_persistent_flags.assert_not_called()

    def test_key_size(self):
        # default cipher is AES-XTS with 512b key
        fmt = LUKS()
        self.assertEqual(fmt.cipher, "aes-xts-plain64")
        self.assertEqual(fmt.key_size, 512)

        # setting cipher shouldn't change the key size
        fmt = LUKS(cipher="aes-xts-plain64")
        self.assertEqual(fmt.key_size, 512)

        # all XTS mode ciphers should default to 512
        fmt = LUKS(cipher="serpent-xts-plain64")
        self.assertEqual(fmt.key_size, 512)

        # no default for non-XTS modes
        fmt = LUKS(cipher="aes-cbc-plain64")
        self.assertEqual(fmt.key_size, 0)

    def test_luks2_pbkdf_memory_fips(self):
        fmt = LUKS(passphrase="passphrase")
        with patch("blivet.formats.luks.blockdev.crypto") as bd:
            # fips enabled, pbkdf memory should not be set
            with patch("blivet.formats.luks.crypto") as crypto:
                attrs = {"is_fips_enabled.return_value": True,
                         "get_optimal_luks_sector_size.return_value": 0,
                         "calculate_luks2_max_memory.return_value": Size("256 MiB")}
                crypto.configure_mock(**attrs)

                fmt._create()
                crypto.calculate_luks2_max_memory.assert_not_called()
                self.assertIsNone(bd.luks_format.call_args[1]["extra"])

            # fips disabled, pbkdf memory should be set
            with patch("blivet.formats.luks.crypto") as crypto:
                attrs = {"is_fips_enabled.return_value": False,
                         "get_optimal_luks_sector_size.return_value": 0,
                         "calculate_luks2_max_memory.return_value": Size("256 MiB")}
                crypto.configure_mock(**attrs)

                fmt._create()
                crypto.calculate_luks2_max_memory.assert_called()
                self.assertEqual(bd.luks_format.call_args[1]["extra"].pbkdf.max_memory_kb, 256 * 1024)

    def test_sector_size_luks1(self):
        fmt = LUKS(passphrase="passphrase")
        self.assertEqual(fmt.luks_sector_size, 0)

        # sector size is not valid for luks1
        with self.assertRaises(ValueError):
            fmt = LUKS(luks_version="luks1", luks_sector_size=4096, passphrase="passphrase")

        # just make sure we won't try to add the extra.sector_size argument ourselves
        fmt = LUKS(luks_version="luks1", passphrase="passphrase")
        with patch("blivet.devices.lvm.blockdev.crypto") as crypto:
            fmt._create()
            crypto.luks_format.assert_called()
            self.assertIsNone(crypto.luks_format.call_args[1]["extra"])

    def test_sector_size_luks2(self):
        fmt = LUKS(passphrase="passphrase")
        self.assertEqual(fmt.luks_sector_size, 0)

        fmt = LUKS(luks_version="luks2", luks_sector_size=4096, passphrase="passphrase")
        self.assertEqual(fmt.luks_sector_size, 4096)

        fmt = LUKS(passphrase="passphrase")
        with patch("blivet.devicelibs.crypto.calculate_luks2_max_memory", return_value=None):
            with patch("blivet.devicelibs.crypto.get_optimal_luks_sector_size", return_value=512):
                with patch("blivet.devices.lvm.blockdev.crypto") as crypto:
                    fmt._create()
                    crypto.luks_format.assert_called()
                    self.assertEqual(crypto.luks_format.call_args[1]["extra"].sector_size, 512)

        fmt = LUKS(passphrase="passphrase")
        with patch("blivet.devicelibs.crypto.calculate_luks2_max_memory", return_value=None):
            with patch("blivet.devicelibs.crypto.get_optimal_luks_sector_size", return_value=0):
                with patch("blivet.devices.lvm.blockdev.crypto") as crypto:
                    fmt._create()
                    crypto.luks_format.assert_called()
                    self.assertIsNone(crypto.luks_format.call_args[1]["extra"])

    def test_header_size(self):
        fmt = LUKS(luks_version="luks2")
        self.assertEqual(fmt._header_size, Size("16 MiB"))
        self.assertEqual(fmt._min_size, Size("16 MiB"))

        fmt = LUKS(luks_version="luks1")
        self.assertEqual(fmt._header_size, Size("2 MiB"))
        self.assertEqual(fmt._min_size, Size("2 MiB"))

        # default is luks2
        fmt = LUKS()
        self.assertEqual(fmt._header_size, Size("16 MiB"))
        self.assertEqual(fmt._min_size, Size("16 MiB"))

    def test_luks_opal(self):
        fmt = LUKS(exists=True)
        self.assertFalse(fmt.is_opal)
        self.assertFalse(fmt.protected)

        fmt = LUKS(luks_version="luks2-hw-opal", exists=True)
        self.assertTrue(fmt.is_opal)
        self.assertTrue(fmt.protected)

        fmt = LUKS(luks_version="luks2-hw-opal", passphrase="passphrase", opal_admin_passphrase="passphrase")
        with patch("blivet.devicelibs.crypto.calculate_luks2_max_memory", return_value=None):
            with patch("blivet.devicelibs.crypto.get_optimal_luks_sector_size", return_value=512):
                with patch("blivet.devices.lvm.blockdev.crypto") as crypto:
                    fmt._create()
                    crypto.luks_format.assert_not_called()
                    crypto.opal_format.assert_called()
                    self.assertEqual(crypto.opal_format.call_args[1]["hw_encryption"],
                                     blockdev.CryptoLUKSHWEncryptionType.OPAL_HW_AND_SW)
                    self.assertEqual(crypto.opal_format.call_args[1]["cipher"], "aes-xts-plain64")
                    self.assertEqual(crypto.opal_format.call_args[1]["key_size"], 512)

        fmt = LUKS(luks_version="luks2-hw-opal-only", passphrase="passphrase", opal_admin_passphrase="passphrase")
        with patch("blivet.devicelibs.crypto.calculate_luks2_max_memory", return_value=None):
            with patch("blivet.devicelibs.crypto.get_optimal_luks_sector_size", return_value=512):
                with patch("blivet.devices.lvm.blockdev.crypto") as crypto:
                    fmt._create()
                    crypto.luks_format.assert_not_called()
                    crypto.opal_format.assert_called()
                    self.assertEqual(crypto.opal_format.call_args[1]["hw_encryption"],
                                     blockdev.CryptoLUKSHWEncryptionType.OPAL_HW_ONLY)

                    # cipher and key size are not valid for HW encryption only
                    self.assertEqual(crypto.opal_format.call_args[1]["cipher"], None)
                    self.assertEqual(crypto.opal_format.call_args[1]["key_size"], 0)

    def test_escrow_packet(self):
        fmt = LUKS(device="/dev/test", passphrase="passphrase", escrow_cert="/tmp/escrow.crt")
        with patch("blivet.devices.lvm.blockdev.crypto") as crypto:
            fmt.escrow(directory="/tmp", backup_passphrase="test")
            crypto.escrow_device.assert_called_with("/dev/test", "passphrase", "/tmp/escrow.crt", "/tmp", None)

        fmt.add_backup_passphrase = True
        with patch("blivet.devices.lvm.blockdev.crypto") as crypto:
            fmt.escrow(directory="/tmp", backup_passphrase="test")
            crypto.escrow_device.assert_called_with("/dev/test", "passphrase", "/tmp/escrow.crt", "/tmp", "test")


class PAESLUKSTestCase(unittest.TestCase):
    def setUp(self):
        encryption_data.pbkdf_args = None
        self.addCleanup(setattr, encryption_data, "pbkdf_args", None)
        for target, kwargs in (("blivet.formats.luks.arch.is_s390", {"return_value": True}),
                               ("blivet.formats.luks.availability.BLOCKDEV_S390_PLUGIN_PAES", {"available": True}),
                               ("blivet.devicelibs.crypto.calculate_luks2_max_memory", {"return_value": None})):
            patcher = patch(target, **kwargs)
            patcher.start()
            self.addCleanup(patcher.stop)

    def new_format(self, **kwargs):
        return LUKS(device="/dev/test", cipher=crypto_lib.PAES_CIPHER, passphrase="secret", **kwargs)

    def test_init(self):
        fmt = self.new_format()
        self.assertTrue(fmt.pervasive)
        self.assertEqual(fmt.key_size, 0)
        self.assertFalse(LUKS().pervasive)
        for version in ("luks1", "luks2-hw-opal", "luks2-hw-opal-only"):
            with self.assertRaises(LUKSError):
                self.new_format(luks_version=version)
        with patch("blivet.formats.luks.arch.is_s390", return_value=False):
            with self.assertRaises(LUKSError):
                self.new_format()
        with patch.object(availability, "BLOCKDEV_S390_PLUGIN_PAES", available=False,
                          availability_errors=["unavailable"]):
            with self.assertRaisesRegex(LUKSError, "unavailable"):
                self.new_format()

    def test_existing_without_paes_support(self):
        with patch("blivet.formats.luks.arch.is_s390", return_value=False), \
                patch.object(availability, "BLOCKDEV_S390_PLUGIN_PAES", available=False,
                             availability_errors=["PAES API unavailable"]):
            fmt = self.new_format(exists=True)
            self.assertTrue(fmt.exists)
            self.assertTrue(fmt.pervasive)
            self.assertEqual(fmt.cipher, crypto_lib.PAES_CIPHER)

        with patch.object(availability, "BLOCKDEV_S390_PLUGIN_PAES", available=False,
                          availability_errors=["PAES API unavailable"]):
            self.assertTrue(self.new_format(exists=True).pervasive)
            with self.assertRaisesRegex(LUKSError, "PAES API unavailable"):
                self.new_format()

    def test_create(self):
        fmt = self.new_format(key_size=512, zkey_key_type="CCA-AESCIPHER", zkey_keybits=256,
                              zkey_apqns=["01.0001"], zkey_sector_size=4096)
        fmt.contexts.add_passphrase("second")
        fmt.contexts.add_keyfile("/key", priority=200)
        info = Mock(key_file_name="/repo/test.skey", secure_key_size=4, sector_size=4096)
        info.name = "blivet-test"
        calls = Mock()
        with patch.object(blockdev, "s390", create=True) as s390, \
                patch.object(crypto_lib, "generate_secure_key", return_value=info) as generate, \
                patch.object(crypto_lib, "read_secure_key", return_value=b"\x00key") as read, \
                patch.object(blockdev, "CryptoKeyslotContext") as constructor, \
                patch.object(blockdev, "crypto") as bdcrypto, \
                patch.object(crypto_lib, "set_verification_pattern") as setvp:
            s390.zkey_list.return_value = []
            calls.attach_mock(generate, "generate")
            calls.attach_mock(read, "read")
            calls.attach_mock(bdcrypto.luks_format_volume_key, "format")
            calls.attach_mock(bdcrypto.luks_add_key, "add_key")
            calls.attach_mock(setvp, "setvp")
            fmt._create()
            self.assertEqual([call[0] for call in calls.mock_calls],
                             ["generate", "read", "format", "add_key", "add_key", "setvp"])
            generate.assert_called_once_with("blivet-test", "CCA-AESCIPHER", 256,
                                             ["/dev/test:luks-test"], ["01.0001"], 4096, False)
            constructor.assert_called_once_with(volume_key=b"\x00key")
            args = bdcrypto.luks_format_volume_key.call_args.kwargs
            self.assertEqual(args["key_size"], 32)
            self.assertEqual(args["cipher"], crypto_lib.PAES_CIPHER)
            self.assertEqual(args["extra"].sector_size, 4096)
            self.assertIs(args["context"], fmt.contexts.get_context("passphrase")._context)
            self.assertIs(args["volume_key"], constructor.return_value)
            bdcrypto.luks_format.assert_not_called()
            setvp.assert_called_once_with("/dev/test", "secret")
            self.assertEqual(fmt._zkey_name, "blivet-test")
            self.assertEqual(fmt.key_size, 32)

    def test_create_failure_cleanup_and_retry(self):
        for stage in ("format", "add_key", "setvp"):
            for requested_name in (None, "custom-key"):
                with self.subTest(stage=stage, requested_name=requested_name), \
                        patch.object(blockdev, "s390", create=True) as s390, \
                        patch.object(crypto_lib, "generate_secure_key") as generate, \
                        patch.object(crypto_lib, "read_secure_key", return_value=b"key"), \
                        patch.object(blockdev, "CryptoKeyslotContext"), \
                        patch.object(blockdev, "crypto") as bdcrypto, \
                        patch.object(crypto_lib, "set_verification_pattern") as setvp, \
                        patch.object(crypto_lib, "remove_secure_key") as remove:
                    repository = []
                    s390.zkey_list.side_effect = lambda name, list_keys=repository.copy: list_keys()
                    info = Mock(key_file_name="/repo/test.skey", secure_key_size=3, sector_size=512)
                    info.name = requested_name or "blivet-test"
                    info.volumes = ["/dev/test:luks-test"]

                    def generate_key(*_args, add_key=repository.append, key_info=info):
                        add_key(key_info)
                        return key_info

                    generate.side_effect = generate_key
                    remove.side_effect = lambda name, clear_keys=repository.clear: clear_keys()
                    fmt = self.new_format(zkey_name=requested_name)
                    fmt.contexts.add_passphrase("second")
                    failing_call = {"format": bdcrypto.luks_format_volume_key,
                                    "add_key": bdcrypto.luks_add_key,
                                    "setvp": setvp}[stage]
                    failing_call.side_effect = blockdev.CryptoError("creation failed")
                    with self.assertRaisesRegex(LUKSError, "creation failed"):
                        fmt._create()
                    remove.assert_called_once_with(info.name)
                    self.assertEqual(repository, [])
                    self.assertFalse(fmt.exists)
                    self.assertEqual(fmt._zkey_name, requested_name)

                    failing_call.side_effect = None
                    fmt._create()
                    self.assertEqual(generate.call_count, 2)
                    self.assertEqual(fmt._zkey_name, info.name)
                    remove.assert_called_once()

    def test_create_cleanup_failure_preserves_original_error(self):
        fmt = self.new_format()

        def prepare():
            fmt._zkey_name = "generated-key"
            return Mock()

        with patch.object(fmt, "_prepare_secure_key", side_effect=prepare), \
                patch.object(fmt, "_create_luks", side_effect=LUKSError("format failed")), \
                patch.object(crypto_lib, "remove_secure_key", side_effect=blockdev.BlockDevError("remove failed")), \
                self.assertLogs("blivet", level="WARNING") as logs:
            with self.assertRaisesRegex(LUKSError, "format failed"):
                fmt._create()
            self.assertEqual(fmt._zkey_name, "generated-key")
            self.assertIn("remove failed", logs.output[0])

    def test_key_collisions(self):
        existing = Mock(volumes=[])
        existing.name = "blivet-test"
        with patch.object(blockdev, "s390", create=True) as s390, \
                patch.object(crypto_lib, "generate_secure_key") as generate, \
                patch.object(crypto_lib, "remove_secure_key") as remove:
            s390.zkey_list.return_value = [existing]
            fmt = self.new_format(zkey_name="blivet-test")
            with self.assertRaisesRegex(LUKSError, "already exists"):
                fmt._create()
            generate.assert_not_called()
            remove.assert_not_called()
            existing.volumes = ["/dev/test:old-map"]
            with self.assertRaisesRegex(LUKSError, "already associated"):
                self.new_format()._create()
            generate.assert_not_called()
            remove.assert_not_called()
            existing.volumes = []
            generate.side_effect = blockdev.BlockDevError("stop after naming")
            with self.assertRaises(LUKSError):
                self.new_format()._prepare_secure_key()
            self.assertEqual(generate.call_args.args[0], "blivet-test-1")

    def test_key_read_failure(self):
        info = Mock(key_file_name="/repo/test.skey")
        info.name = "blivet-test"
        with patch.object(blockdev, "s390", create=True) as s390, \
                patch.object(crypto_lib, "generate_secure_key", return_value=info), \
                patch.object(crypto_lib, "read_secure_key", side_effect=OSError("unreadable")), \
                patch.object(crypto_lib, "remove_secure_key") as remove:
            s390.zkey_list.return_value = []
            fmt = self.new_format()
            with self.assertRaises(LUKSError):
                fmt._prepare_secure_key()
            remove.assert_called_once_with("blivet-test")
            self.assertIsNone(fmt._zkey_name)

    def test_missing_passphrase(self):
        fmt = LUKS(device="/dev/test", cipher=crypto_lib.PAES_CIPHER, key_file="/key")
        with patch.object(crypto_lib, "generate_secure_key") as generate:
            with self.assertRaisesRegex(LUKSError, "requires a passphrase"):
                fmt._create()
            generate.assert_not_called()

    def test_destroy(self):
        for cached in (True, False):
            with self.subTest(cached=cached), \
                    patch.object(DeviceFormat, "_pre_destroy"), \
                    patch.object(DeviceFormat, "_destroy"), \
                    patch("blivet.formats.udev.settle"), \
                    patch.object(crypto_lib, "find_secure_key_for_volume") as find, \
                    patch.object(crypto_lib, "remove_secure_key") as remove:
                fmt = self.new_format(exists=True, zkey_name="test-key" if cached else None)
                find.return_value.name = "test-key"
                find.return_value.volumes = ["/dev/test:luks-test", "/dev/../dev/test:alias-map"]
                fmt.destroy()
                remove.assert_called_once_with("test-key")
                self.assertFalse(fmt.exists)
                self.assertIsNone(fmt._zkey_name)
                find.assert_called_once_with("/dev/test")

    def test_destroy_preserves_shared_key(self):
        for cached in (True, False):
            with self.subTest(cached=cached), \
                    patch.object(DeviceFormat, "_pre_destroy"), \
                    patch.object(DeviceFormat, "_destroy"), \
                    patch("blivet.formats.udev.settle"), \
                    patch.object(crypto_lib, "find_secure_key_for_volume") as find, \
                    patch.object(crypto_lib, "remove_secure_key") as remove, \
                    self.assertLogs("blivet", level="WARNING") as logs:
                fmt = self.new_format(exists=True, zkey_name="shared-key" if cached else None)
                find.return_value.name = "shared-key"
                find.return_value.volumes = ["/dev/test:luks-test", "/dev/other:luks-other"]
                fmt.destroy()
                self.assertFalse(fmt.exists)
                find.assert_called_once_with("/dev/test")
                remove.assert_not_called()
                self.assertIn("Keeping shared secure key shared-key", logs.output[0])
                self.assertIn("/dev/other:luks-other", logs.output[0])

    def test_destroy_preserves_key_when_lookup_fails(self):
        fmt = self.new_format(exists=True, zkey_name="test-key")
        with patch("blivet.formats.udev.settle"), \
                patch.object(crypto_lib, "find_secure_key_for_volume", side_effect=blockdev.BlockDevError("lookup failed")), \
                patch.object(crypto_lib, "remove_secure_key") as remove, \
                self.assertLogs("blivet", level="WARNING") as logs:
            fmt._post_destroy()
            self.assertFalse(fmt.exists)
            remove.assert_not_called()
            self.assertIn("lookup failed", logs.output[0])

    def test_destroy_failures(self):
        fmt = self.new_format(exists=True, zkey_name="test-key")
        with patch.object(DeviceFormat, "_pre_destroy"), \
                patch.object(DeviceFormat, "_destroy", side_effect=FormatDestroyError("failed")), \
                patch.object(crypto_lib, "remove_secure_key") as remove:
            with self.assertRaises(FormatDestroyError):
                fmt.destroy()
            remove.assert_not_called()
        with patch("blivet.formats.udev.settle"), \
                patch.object(crypto_lib, "find_secure_key_for_volume") as find, \
                patch.object(crypto_lib, "remove_secure_key", side_effect=blockdev.BlockDevError("failed")) as remove:
            find.return_value.name = "test-key"
            find.return_value.volumes = ["/dev/test:luks-test"]
            fmt._post_destroy()
            remove.assert_called_once_with("test-key")
            self.assertFalse(fmt.exists)
