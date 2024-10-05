function Show-BTLogo {
    param(
        [string]$Version
    )

    $BGColor = $host.UI.RawUI.BackgroundColor

    Write-Host ' ' -BackgroundColor $BGColor
    Write-Host '        :::::::::  :::       :::    ::: :::::::::: ::::::::::: :::    ::: :::    ::: :::::::::: :::::::::   ::::::::  ' -ForegroundColor DarkMagenta -BackgroundColor Black -NoNewline
    Write-Host ' ' -BackgroundColor $BGColor
    Write-Host '       :+:    :+: :+:       :+:    :+: :+:            :+:     :+:    :+: :+:    :+: :+:        :+:    :+: :+:    :+:  ' -ForegroundColor Magenta -BackgroundColor Black -NoNewline
    Write-Host ' ' -BackgroundColor $BGColor
    Write-Host '      +:+    +:+ +:+       +:+    +:+ +:+            +:+     +:+    +:+  +:+  +:+  +:+        +:+    +:+ +:+    +:+   ' -ForegroundColor Magenta -BackgroundColor Black -NoNewline
    Write-Host ' ' -BackgroundColor $BGColor
    Write-Host '     +#++:++#+  +#+       +#+    +:+ +#++:++#       +#+     +#+    +:+   +#++:+   +#++:++#   +#+    +:+ +#+    +:+    ' -ForegroundColor DarkBlue -BackgroundColor Black -NoNewline
    Write-Host ' ' -BackgroundColor $BGColor
    Write-Host '    +#+    +#+ +#+       +#+    +#+ +#+            +#+     +#+    +#+  +#+  +#+  +#+        +#+    +#+ +#+    +#+     ' -ForegroundColor DarkBlue -BackgroundColor Black -NoNewline
    Write-Host ' ' -BackgroundColor $BGColor
    Write-Host '   #+#    #+# #+#       #+#    #+# #+#            #+#     #+#    #+# #+#    #+# #+#        #+#    #+# #+#    #+#      ' -ForegroundColor Blue -BackgroundColor Black -NoNewline
    Write-Host ' ' -BackgroundColor $BGColor
    Write-Host '  #########  ######### #########  ##########     ###      ########  ###    ### ########## #########   ########        ' -ForegroundColor Blue -BackgroundColor Black -NoNewline
    Write-Host ' ' -BackgroundColor $BGColor
    Write-Host ' ' -BackgroundColor $BGColor
    Write-Host "                                                                                                      v$Version"
}
