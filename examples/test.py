import unittest
import check_sec_updates
from StringIO import StringIO

class TestExitCodes(unittest.TestCase):

    def test_ok(self):
        s = StringIO(
"""
1488124984 redhat-release-server 6Server 6.9.0.4.el6
1258685031 bc 1.06.95 1.el6
1276766929 gstreamer 0.10.29 1.el6
""")
        with self.assertRaises(SystemExit) as cm:
            check_sec_updates.main(input = s, quiet = True)
        self.assertEqual(cm.exception.code, 0, 'Must exit with OK')

    def test_warning(self):
        s = StringIO(
"""
1176766929 redhat-release 5Server 5.9.0.5
576766929 hypervkvpd 0 0.6
""")
        with self.assertRaises(SystemExit) as cm:
            check_sec_updates.main(input = s, quiet = True)
        self.assertEqual(cm.exception.code, 1, 'Must exit with WARNING (1)')

    def test_critical(self):
        s = StringIO(
"""
1488124984 redhat-release-server 6Server 6.9.0.4.el6
# This one has an important CVE
1425043132 pcre 7.8 7.el6
""")
        with self.assertRaises(SystemExit) as cm:
            check_sec_updates.main(input = s, quiet = True)
        self.assertEqual(cm.exception.code, 2, 'Must exit with CRITICAL (2)')

    def test_unknown(self):
        s = StringIO(
"""
1488124984 redhat-release-server 6Server 6.9.0.4.el6
# This is a b0rken entry
1425043132 pcre
""")
        with self.assertRaises(SystemExit) as cm:
            check_sec_updates.main(input = s, quiet = True)
        self.assertEqual(cm.exception.code, 3, 'Must exit with UNKNOWN (3)')



if __name__ == '__main__':
    unittest.main()
