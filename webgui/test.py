import phonenumbers as phone
from phonenumbers import timezone,geocoder,carrier
number = input("Enter Phone number with country code +_ _ :  ")
number=phone.parse(number)
time=timezone.time_zones_for_number(number)
carrier_company=carrier.name_for_number(number, "en")
region=geocoder.description_for_number(number, "en") 

print(number)
print(time)
print(carrier_company)
print(region)