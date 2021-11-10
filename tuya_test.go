package tuyaslim

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"
)

func TestGetDevices(t *testing.T) {
	ctx := context.Background()
	client := NewClient(os.Getenv("TUYA_CLIENT_ID"), os.Getenv("TUYA_CLIENT_SECRET"))
	devices, err := client.GetDevices(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(devices) == 0 {
		t.Error("devices should not be empty")
	}
	t.Log("received", len(devices), "devices")
	var onlineDevice *Device
	var switchCmd string
	for _, device := range devices {
		if !device.Online {
			continue
		}
		switchCmd = ""
		for key := range device.Statuses {
			if strings.HasPrefix(key, "switch") {
				switchCmd = key
				break
			}
		}
		if switchCmd == "" {
			continue
		}
		onlineDevice = &device
	}
	if onlineDevice == nil || switchCmd == "" {
		t.Log("no online device to test")
		return
	}
	t.Log("selected online device:", onlineDevice)
	for i := 5; i > 0; i-- {
		t.Log("will switch on then off this device in", i, "seconds")
		time.Sleep(1 * time.Second)
	}
	t.Log("switching on...")
	if err := client.Execute(ctx, onlineDevice.Id, switchCmd, true); err != nil {
		t.Error(err)
	}
	time.Sleep(2 * time.Second)
	t.Log("switching off...")
	if err := client.Execute(ctx, onlineDevice.Id, switchCmd, false); err != nil {
		t.Error(err)
	}
}
