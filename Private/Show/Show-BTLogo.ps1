function Show-BTLogo {
    param(
        [string]$Version
    )

    Write-Host '      ::::::::: :::      :::    :::::::::::::::::::::::::::    ::::::    ::::::::::::::::::::::  :::::::: ' -ForegroundColor DarkMagenta
    Write-Host '     :+:    :+::+:      :+:    :+::+:           :+:    :+:    :+::+:    :+::+:       :+:    :+::+:    :+: ' -ForegroundColor Magenta
    Write-Host '    +:+    +:++:+      +:+    +:++:+           +:+    +:+    +:+ +:+  +:+ +:+       +:+    +:++:+    +:+  ' -ForegroundColor Magenta
    Write-Host '   +#++:++#+ +#+      +#+    +:++#++:++#      +#+    +#+    +:+  +#++:+  +#++:++#  +#+    +:++#+    +:+   ' -ForegroundColor DarkBlue
    Write-Host '  +#+    +#++#+      +#+    +#++#+           +#+    +#+    +#+ +#+  +#+ +#+       +#+    +#++#+    +#+    ' -ForegroundColor DarkBlue
    Write-Host ' #+#    #+##+#      #+#    #+##+#           #+#    #+#    #+##+#    #+##+#       #+#    #+##+#    #+#     ' -ForegroundColor Blue
    Write-Host '######### ################## ##########    ###     ######## ###    ######################  ########       ' -ForegroundColor Blue
    Write-Host "                                                                                           v$Version"   
}