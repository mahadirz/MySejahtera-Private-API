import cbor2
from api import MysejahteraPrivateAPI
import cv2
from pyzbar import pyzbar
import imutils
import RPi.GPIO as GPIO
import time
import traceback
from multiprocessing import Process

GPIO.setmode(GPIO.BCM)

# set up camera object
cap = cv2.VideoCapture(0)

# QR code detection object
detector = cv2.QRCodeDetector()


red = 23
green = 24
blue = 25

GPIO.setup(red, GPIO.OUT)
GPIO.setup(green, GPIO.OUT)
GPIO.setup(blue, GPIO.OUT)

def reset_led():
	GPIO.output(red, 0)
	GPIO.output(green, 0)
	GPIO.output(blue, 0)

def led_blink(seq):
	for i in range(100):
		for i in seq:
			GPIO.output(red,i.lower()=="r")
			GPIO.output(green,i.lower()=="g")
			GPIO.output(blue,i.lower()=="b")
			time.sleep(0.2)
	reset_led()

reset_led()  
p = None

try:    
	while True:
		# get the image
		_, frame = cap.read()
		frame = imutils.resize(frame, width=400)
		barcodes = pyzbar.decode(frame)
		
		# if there is a bounding box, draw one, along with the data
		for barcode in barcodes:
			(x,y,w,h) = barcode.rect
			barcode_data = barcode.data.decode("utf-8")
			barcode_type = barcode.type
			print(barcode_data,barcode_type)
			
			try:
				cose_msg = MysejahteraPrivateAPI.decode_vaccine_cert(barcode_data)
				if MysejahteraPrivateAPI.verify_signature(cose_msg):
					print("valid")
					if p is not None:
						p.terminate()
						p = None
					reset_led()
					p = Process(target=led_blink, args=("G0",))
					p.start()
				else:
					print("Invalid")
					if p is not None:
						p.terminate()
						p = None
					reset_led()
					p = Process(target=led_blink, args=("R0",))
					p.start()
					
				# TODO check 2nd dose date for fully vaccinated status
				cbor = cbor2.loads(cose_msg.payload)
				# ....
			except:
				print(traceback.print_exc())
				if p is not None:
					p.terminate()
					p = None
				reset_led()
				p = Process(target=led_blink, args=("BR",))
				p.start()
			
			cv2.rectangle(frame, (x,y), (x+w, y+h), (0,0,255), 2)
				
		# display the image preview
		cv2.imshow("code detector", frame)
		
		if(cv2.waitKey(1) == ord("q")):
			break

except KeyboardInterrupt:
    GPIO.cleanup()
        
# free camera object and exit
cap.release()
cv2.destroyAllWindows()
GPIO.cleanup()
