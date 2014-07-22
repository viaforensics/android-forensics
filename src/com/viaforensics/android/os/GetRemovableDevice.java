/*
    This file is part of AFL-OSE (AFLogical - Open Source Edition).

    AFL-OSE is a framework for the forensic logical extraction of data 
    from Android devices.

    Copyright �� 2011 viaForensics LLC
 
    AFL-OSE is available under the terms of multiple licenses.
 
    For academic, research, and experimental purposes, AFL-OSE is 
    free software: you can redistribute it and / or modify it under 
    the terms of the GNU General Public License as published by the 
    Free Software Foundation, version 3.  The source code must be made 
    available and this license must be retained.  It is distributed in 
    the hope that it will be useful, but WITHOUT ANY WARRANTY; without 
    even the implied warranty of FITNESS FOR A PARTICULAR PURPOSE.  
    See the GNU General Public License at http://www.gnu.org/licenses/ 
    for more details.
 
    For any other purposes, this file may not be used except under the 
    terms of a commercial license granted from viaForensics.  For 
    commercial license details, contact viaForensics at 
    http://viaforensics.com/contact-us/.
 */

package com.viaforensics.android.os;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;

import com.viaforensics.android.logs.DebugLogger;

public class GetRemovableDevice {

	public GetRemovableDevice() {
	}
	
	public static String[] getDirectories() {
//		DebugLogger.d(com.viaforensics.android.ForensicsActivity.TAG, "getDirectories");
		File tempFile;
		String[] directories = null;
		String[] splits;
		ArrayList<String> arrayList = new ArrayList<String>();
		BufferedReader bufferedReader = null;
		String lineRead;

		try {
			arrayList.clear();
			bufferedReader = new BufferedReader(new FileReader("/proc/mounts"));

			while ((lineRead = bufferedReader.readLine()) != null) {
//				DebugLogger.d(com.viaforensics.android.ForensicsActivity.TAG, "lineRead: " + lineRead);
				splits = lineRead.split(" ");

				// System external storage
//				if (splits[1].equals(Environment.getExternalStorageDirectory().getPath())) {
//					arrayList.add(splits[1]);
//					DebugLogger.d(TAG, "gesd split 1: " + splits[1]);
//					continue;
//				}

				// skip if not external storage device
				if (!splits[0].contains("/dev/block/")) {
					continue;
				}

				// skip if mtdblock device
				if (splits[0].contains("/dev/block/mtdblock")) {
					continue;
				}

	            // skip if not in vfat node
	            if (!splits[2].contains("vfat")) {
	                continue;
	            }

				// skip if not in /mnt node
//				if (!splits[1].contains("/mnt")) {
//					continue;
//				}

				// skip these names
				if (splits[1].contains("/secure")) {
					continue;
				}

				if (splits[1].contains("/mnt/asec")) {
					continue;
				}

				// Eliminate if not a directory or fully accessible
				tempFile = new File(splits[1]);
				if (!tempFile.exists()) {
					continue;
				}
				if (!tempFile.isDirectory()) {
					continue;
				}
				if (!tempFile.canRead()) {
					continue;
				}
				if (!tempFile.canWrite()) {
					continue;
				}

				// Met all the criteria, assume sdcard
				arrayList.add(splits[1]);
			}

		} catch (FileNotFoundException e) {
		} catch (IOException e) {
		} finally {
			if (bufferedReader != null) {
				try {
					bufferedReader.close();
				} catch (IOException e) {
				}
			}
		}

		// Send list back to caller
		if (arrayList.size() == 0) {
			arrayList.add("sdcard not found");
		}
		directories = new String[arrayList.size()];
		for (int i = 0; i < arrayList.size(); i++) {
			directories[i] = arrayList.get(i);
		}
		return directories;
	}
}
