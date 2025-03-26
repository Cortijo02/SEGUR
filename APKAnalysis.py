import sys
from androguard import misc
from loguru import logger
import collections
import argparse
import csv
import multiprocessing
from filehash import FileHash
import os


def extractFeaturesAPK(path):
	static_analysis_dict = collections.OrderedDict()
	try:
		logger.remove()
		logger.add(sys.stderr, level="WARNING")
		# Analizar APKs
		a, d, dx = misc.AnalyzeAPK(path)
		#md5 hash
		hasher = FileHash('md5')
		# Calculate the MD5 hash of the file
		static_analysis_dict['hash'] = hasher.hash_file(path)
		# Package name
		static_analysis_dict['PackageName'] = a.get_package()

		with open("DefaultPermList.txt", 'r') as file:
			default_permission_list = [line.strip() for line in file]

		# APK features
		if a.get_min_sdk_version() is not None:
			static_analysis_dict['min_andrversion'] = str(a.get_min_sdk_version())
		else:
			static_analysis_dict['min_andrversion'] = 0
		if a.get_max_sdk_version() is not None:
			static_analysis_dict['max_andrversion'] = str(a.get_max_sdk_version())
		else:
			static_analysis_dict['max_andrversion'] = 0
		if a.get_target_sdk_version() is not None:
			static_analysis_dict['target_andrversion'] = str(a.get_target_sdk_version())
		else:
			static_analysis_dict['target_andrversion'] = 0



		# Permissions
		app_permission_list = a.get_permissions()
		for permission in default_permission_list:
			if permission in app_permission_list:
				static_analysis_dict[permission] = 1
			else:
				static_analysis_dict[permission] = 0
		static_analysis_dict['PermissionCount'] = len(a.get_permissions())
		static_analysis_dict['DefaultPermissionCount'] = len([item for item in app_permission_list if item in default_permission_list])

		#Activities, Services, etc.
		static_analysis_dict['activityCount'] = len(a.get_activities())
		# serviceCount
		static_analysis_dict['serviceCount'] = len(a.get_services())
		# receiverCount
		static_analysis_dict['receiverCount'] = len(a.get_receivers())
		# providerCount
		static_analysis_dict['providerCount'] = len(a.get_providers())
		# exportedCount, previously all zero
		static_analysis_dict['exportedCount'] = 0
		for activity in a.get_android_manifest_xml().findall(".//{}".format('activity')):
			if activity.get('android:exported') == 'true':
				static_analysis_dict['exportedCount'] += 1
		for service in a.get_android_manifest_xml().findall(".//{}".format('service')):
			if service.get('android:exported') == 'true':
				static_analysis_dict['exportedCount'] += 1
		for receiver in a.get_android_manifest_xml().findall(".//{}".format('receiver')):
			if receiver.get('android:exported') == 'true':
				static_analysis_dict['exportedCount'] += 1
		for provider in a.get_android_manifest_xml().findall(".//{}".format('provider')):
			if provider.get('android:exported') == 'true':
				static_analysis_dict['exportedCount'] += 1



		# Varios counts
		static_analysis_dict['MethodCount'] = len(list(dx.find_methods()))
		static_analysis_dict['ClassCount'] = len(d[0].get_classes())
		static_analysis_dict['CryptoCount'] = len(list(dx.find_methods(classname=r"Ljavax\/crypto\/\S*")))
		static_analysis_dict['DynCodeCount'] = len(list(dx.find_methods(classname=r"Ldalvik\/system\/DexClassLoader\/\S*")))
		static_analysis_dict['NativeCount'] =  len(list(dx.find_methods(classname=r"Ljava\/lang\/System\/\S*")))
		static_analysis_dict['ReflectionCount'] = len(list(dx.find_methods(classname=r"Ljava\/lang\/reflect\/Method\/\S*")))
		static_analysis_dict['FileCount'] = len(a.get_files())
		# API features
		# sendSMS
		if (len(list(dx.find_methods(classname=r'Landroid\/telephony\/SmsManager;', methodname=r'send[a-zA-Z]+Message'))) > 0) or (len(list(dx.find_methods(classname=r'Landroid\/telephony\/SmsManager;', methodname=r'send[a-zA-Z]+Message'))) > 0):
			static_analysis_dict['SendSMS'] = 1
		else:
			static_analysis_dict['SendSMS'] = 0
		# deleteSMS, previously all zero
		if len(list(dx.find_methods(classname=r'Landroid\/content\/ContentResolver;', methodname='delete'))) > 0:
			static_analysis_dict['deleteSMS']  = 1
		else:
			static_analysis_dict['deleteSMS'] = 0
		# interruptSMS
		if len(list(dx.find_methods(classname=r'Landroid\/content\/BroadcastReceiver;', methodname='abortBroadcast'))) > 0:
			static_analysis_dict['interruptSMS'] = 1
		else:
			static_analysis_dict['interruptSMS'] = 0
		# httpPost
		if (len(list(dx.find_methods(classname=r'Lorg\/apache\/http\/client\/methods\/HttpPost;'))) > 0) or (len(list(dx.find_methods(classname=r'Ljava\/net\/HttpURLConnection;'))) > 0):
			static_analysis_dict['httpPost'] = 1
		else:
			static_analysis_dict['httpPost'] = 0
		# deviceId
		if len(list(dx.find_methods(classname=r'Landroid\/telephony\/TelephonyManager;', methodname='getDeviceId'))) > 0:
			static_analysis_dict['deviceId'] = 1
		else:
			static_analysis_dict['deviceId'] = 0
		# simCountry
		if len(list(dx.find_methods(classname=r'Landroid\/telephony\/TelephonyManager;', methodname='getSimCountryIso'))) > 0:
			static_analysis_dict['simCountry'] = 1
		else:
			static_analysis_dict['simCountry'] = 0
		# installedPkg
		if len(list(dx.find_methods(classname=r'Landroid\/content\/pm\/PackageManager;', methodname='getInstalledPackages'))) > 0:
			static_analysis_dict['installedPkg'] = 1
		else:
			static_analysis_dict['installedPkg'] = 0
		# subprocess
		if (len(list(dx.find_methods(classname=r'Ljava\/lang\/ProcessBuilder;',methodname='start'))) > 0) or (len(list(dx.find_methods(classname=r'Ljava\/lang\/Runtime;',methodname='exec'))) > 0):
			static_analysis_dict['subprocess'] = 1
		else:
			static_analysis_dict['subprocess'] = 0
		# jni
		if len(list(dx.find_methods(classname=r'Ljava\/lang\/System;', methodname='loadLibrary'))) > 0:
			static_analysis_dict['jni'] = 1
		else:
			static_analysis_dict['jni'] = 0

		# Widget features
		static_analysis_dict['buttonCount'] = len(list(dx.find_fields(classname=r'L\S*Button\S*')))
		static_analysis_dict['TextViewCount'] = len(list(dx.find_fields(classname=r'L\S*TextView\S*')))
		static_analysis_dict['EditViewCount'] = len(list(dx.find_fields(classname=r'L\S*EditText\S*')))
		static_analysis_dict['ImageButtonCount'] = len(list(dx.find_fields(classname=r'L\S*ImageButton\S*')))
		static_analysis_dict['CheckBoxCount'] = len(list(dx.find_fields(classname=r'L\S*CheckBox\S*')))
		static_analysis_dict['RadioGroupCount'] = len(list(dx.find_fields(classname=r'L\S*RadioGroup\S*')))
		static_analysis_dict['RadioButtonCount'] = len(list(dx.find_fields(classname=r'L\S*RadioButton\S*')))
		static_analysis_dict['ToastCount'] = len(list(dx.find_fields(classname=r'L\S*Toast\S*')))
		static_analysis_dict['SpinnerCount'] = len(list(dx.find_fields(classname=r'L\S*Spinner\S*')))
		static_analysis_dict['ListViewCount'] = len(list(dx.find_fields(classname=r'L\S*ListView\S*')))
	except:
		return []
	return static_analysis_dict

# Main function
def main():
    parser = argparse.ArgumentParser(description="Analyze APK files with Androguard.")
    parser.add_argument("--input", "-i", default=".", help="Folder where the APKs are.")
    parser.add_argument("--output", "-o", default=".", help="CSV output file")
    args = parser.parse_args()

    if not os.path.exists(args.input):
        print("Input file not found.")
        return

    apks_to_analyze = [os.path.join(args.input, file_name) for file_name in os.listdir(args.input) if file_name.endswith(".apk")]

    num_cpus = multiprocessing.cpu_count()
    pool = multiprocessing.Pool(processes=num_cpus)
    results = []
    for result in pool.imap_unordered(extractFeaturesAPK, apks_to_analyze, chunksize=1):
        if len(result)>0:
            results.append(result)

    pool.close()
    pool.join()
	
    print("Finished processing")
    fieldnames = results[0].keys()

	# Write the list of dictionaries to the CSV file
    with open(f"{args.output}_features.csv", 'w', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        # Write the header
        writer.writeheader()
    	# Write the data
        writer.writerows(results)
    print("Finished Everything!")


if __name__ == "__main__":
    main()