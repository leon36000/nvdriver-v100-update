/* SPDX-License-Identifier: MIT */
void init(void)
{
    nvUvmInterfaceSessionCreate(&session, &platform);
    nvUvmInterfaceRegisterUvmCallbacks(&ops);
}
