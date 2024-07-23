function Show-BTLogo {
    param(
        [string]$Version
    )

    Write-Host '      ::::::::: :::      :::    :::::::::::::::::::::::::::    ::::::    ::::::::::::::::::::::  :::::::: ' -ForegroundColor DarkMagenta -BackgroundColor Black
    Write-Host '     :+:    :+::+:      :+:    :+::+:           :+:    :+:    :+::+:    :+::+:       :+:    :+::+:    :+: ' -ForegroundColor Magenta -BackgroundColor Black
    Write-Host '    +:+    +:++:+      +:+    +:++:+           +:+    +:+    +:+ +:+  +:+ +:+       +:+    +:++:+    +:+  ' -ForegroundColor Magenta -BackgroundColor Black
    Write-Host '   +#++:++#+ +#+      +#+    +:++#++:++#      +#+    +#+    +:+  +#++:+  +#++:++#  +#+    +:++#+    +:+   ' -ForegroundColor DarkBlue -BackgroundColor Black
    Write-Host '  +#+    +#++#+      +#+    +#++#+           +#+    +#+    +#+ +#+  +#+ +#+       +#+    +#++#+    +#+    ' -ForegroundColor DarkBlue -BackgroundColor Black
    Write-Host ' #+#    #+##+#      #+#    #+##+#           #+#    #+#    #+##+#    #+##+#       #+#    #+##+#    #+#     ' -ForegroundColor Blue -BackgroundColor Black
    Write-Host '######### ################## ##########    ###     ######## ###    ######################  ########       ' -ForegroundColor Blue -BackgroundColor Black
    Write-Host "                                                                                           v$Version"   
}
