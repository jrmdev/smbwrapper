Set objWMIService = GetObject("winmgmts:\\.\root\cimv2")
Set colListOfServices = objWMIService.ExecQuery("Select * from Win32_Service Where Name ='VSS'")

For Each objService in colListOfServices
  If objService.State = "Stopped" Then
	objService.StartService()
	InitState = True
  End If
Next

Set objShadowStorage = objWMIService.Get("Win32_ShadowCopy")
errResult = objShadowStorage.Create("C:\", "ClientAccessible", strShadowID)

Set colItems = objWMIService.ExecQuery("Select * from Win32_ShadowCopy")
For Each objItem in colItems
  If objItem.ID = strShadowID Then
	Set objShell = WScript.CreateObject("WScript.Shell")    
	objResult = objShell.Run("cmd /C copy /Y "& objItem.DeviceObject & WScript.Arguments.Item(0) & " C:\WINDOWS\Temp\temp.tmp", 0, True)
	errResult = objItem.Delete_
  End If
Next

If InitState = True Then
  Set colListOfServices = objWMIService.ExecQuery("Select * from Win32_Service Where Name ='VSS'")
  For Each objService in colListOfServices
    objService.StopService()
  Next
End If

wscript.Quit(0)
