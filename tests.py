from unittest.mock import MagicMock
import unittest
import main

class Tests(unittest.TestCase):

	def test_db_setup(self):
		db = main.setupDatabase()
		self.assertEqual(0, 0)

	def test_int_to_base64(self):
		output = str(main.int_to_base64(1234567891011121314151617181920))
		self.assertEqual(output, "D5Uan9PBWK_f8Iq44A")

	def test_insert_key(self):
		dbinfo = main.setupDatabase()
		try:
			main.insertKey("0000", main.int_to_base64(1234567891011121314151617181920), 80000, dbinfo)
			self.assertEqual(0,0)
		except:
			self.assertEqual(0,1)

	def test_insert_expired_key(self):
		dbinfo = main.setupDatabase()
		try:
			main.insert_expired_key(dbinfo)
			self.assertEqual(0,0)
		except:
			self.assertEqual(0,1)
	
	# def test_server(self):
	# 	#just checking to make sure that none of the code throws an exception
	# 	try:
	# 		self.server.do_DELETE()
	# 		self.server.do_GET()
	# 		self.server.do_HEAD()
	# 		self.server.do_PATCH()
	# 		self.server.do_POST()
	# 		self.server.do_PUT()

	# 		self.server.server_close()
	# 		self.assertEqual(0, 0)
	# 	except:
	# 		self.assertEqual(0, 1)