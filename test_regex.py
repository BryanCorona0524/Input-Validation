import unittest
import app

class TestRegex(unittest.TestCase):
    def test_name_regex(self):
        '''
        Acceptable formats for name:
        '''
        self.assertTrue(app.valid_name("Bruce Schneier"))
        self.assertTrue(app.valid_name("Schneier, Bruce"))
        self.assertTrue(app.valid_name("Schneier, Bruce Wayne"))
        self.assertTrue(app.valid_name("O’Malley, John F."))
        self.assertTrue(app.valid_name("John O’Malley-Smith"))
        self.assertTrue(app.valid_name("Cher"))
        '''
        Unacceptable formats for name:
        '''
        self.assertFalse(app.valid_name("Ron O’’Henry"))
        self.assertFalse(app.valid_name("Ron O’Henry-Smith-Barnes"))    
        self.assertFalse(app.valid_name("L33t Hacker"))
        self.assertFalse(app.valid_name("<Script>alert(“XSS”)</Script>"))
        self.assertFalse(app.valid_name("Brad Everett Samuel Smith"))
        self.assertFalse(app.valid_name("select * from users;"))
        '''
        Student provided test inputs:
        '''
        self.assertTrue(app.valid_name("Bryan Alexis C’orona-Rangel"))
        self.assertTrue(app.valid_name("Rangel, Bryan"))
        self.assertTrue(app.valid_name("Corona-Rangel, Bryan A."))
        self.assertFalse(app.valid_name("Bryan Alexis C’orona-Rangel, Bryan"))
        self.assertFalse(app.valid_name("Rangel, Bryan O-Malley"))
        self.assertFalse(app.valid_name("C'orona--Rangel, Bryan A"))

    def test_number_regex(self):
        '''
        Acceptable formats for phone numbers:
        '''
        self.assertTrue(app.valid_phone_number("12345"))
        self.assertTrue(app.valid_phone_number("(703)111-2121"))
        self.assertTrue(app.valid_phone_number("123-1234"))
        self.assertTrue(app.valid_phone_number("+1(703)111-2121"))
        self.assertTrue(app.valid_phone_number("+32 (21) 212-2324"))
        self.assertTrue(app.valid_phone_number("1(703)123-1234"))
        self.assertTrue(app.valid_phone_number("011 701 111 1234"))
        self.assertTrue(app.valid_phone_number("12345.12345"))
        self.assertTrue(app.valid_phone_number("011 1 703 111 1234"))
        '''
        Unacceptable formats for phone numbers:
        '''
        self.assertFalse(app.valid_phone_number("123"))
        self.assertFalse(app.valid_phone_number("1/703/123/1234"))
        self.assertFalse(app.valid_phone_number("Nr 102-123-1234"))
        self.assertFalse(app.valid_phone_number("<script>alert(“XSS”)</script>"))
        self.assertFalse(app.valid_phone_number("7031111234"))
        self.assertFalse(app.valid_phone_number("+1234 (201) 123-1234"))
        self.assertFalse(app.valid_phone_number("(001) 123-1234"))
        self.assertFalse(app.valid_phone_number("+01 (703) 123-1234"))
        self.assertFalse(app.valid_phone_number("(703) 123-1234 ext 204"))
        '''
        Student provided test inputs:
        '''
        self.assertTrue(app.valid_phone_number("12 12 12 12"))
        self.assertTrue(app.valid_phone_number("1212 1212"))
        self.assertTrue(app.valid_phone_number("12.12.12.12"))
        self.assertTrue(app.valid_phone_number("1212.1212"))
        self.assertTrue(app.valid_phone_number("+45 12 12 12 12"))
        self.assertTrue(app.valid_phone_number("+45 1212 1212"))
        self.assertFalse(app.valid_phone_number("+12 12 12 12"))
        self.assertFalse(app.valid_phone_number("+12345"))

if __name__ == '__main__':
    unittest.main()