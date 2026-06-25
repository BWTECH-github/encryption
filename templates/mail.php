<?php
/** @var OC_Theme $theme */
/** @var array $_ */
?>
<table cellspacing="0" cellpadding="0" border="0" width="100%">
	<tr><td>
			<table cellspacing="0" cellpadding="0" border="0" width="600px">
				<tr>
					<td colspan="2" style="padding:0;">
						<table cellspacing="0" cellpadding="0" border="0" width="100%">
							<tr><td style="height:4px;line-height:4px;font-size:0;background-color:<?php p($theme->getMailHeaderColor()); ?>;">&nbsp;</td></tr>
							<tr><td align="center" style="padding:26px 0 14px;background-color:#ffffff;"><img src="<?php p(\OC::$server->getURLGenerator()->getAbsoluteURL(image_path('', 'logo-mail.gif'))); ?>" alt="<?php p($theme->getName()); ?>" style="display:block;margin:0 auto;border:0;max-width:210px;height:auto;"></td></tr>
						</table>
					</td>
				</tr>
				<tr><td colspan="2">&nbsp;</td></tr>
				<tr>
					<td width="20px">&nbsp;</td>
					<td style="font-weight:normal; font-size:0.8em; line-height:1.2em; font-family:verdana,'arial',sans;">
						<?php
						print_unescaped($l->t('Hey there,<br><br>the admin enabled server-side-encryption. Your files were encrypted using the password <strong>%s</strong>.<br><br>Please login to the web interface, go to the section "ownCloud basic encryption module" of your personal settings and update your encryption password by entering this password into the "old log-in password" field and your current login-password.<br><br>', [$_['password']]));
?>
					</td>
				</tr>
				<tr><td colspan="2">&nbsp;</td></tr>
				<tr>
					<td width="20px">&nbsp;</td>
					<td style="font-weight:normal; font-size:0.8em; line-height:1.2em; font-family:verdana,'arial',sans;">
						<?php print_unescaped($this->inc('html.mail.footer')); ?>
					</td>
				</tr>
				<tr>
					<td colspan="2">&nbsp;</td>
				</tr>
			</table>
		</td></tr>
</table>
