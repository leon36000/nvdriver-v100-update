# Read-only status-semantics review packet

Current source snippets only. Do not modify files. Distinguish Linux syscall transport errors from `NVOS54_PARAMETERS.status` embedded RM results. The repository suite just passed 2,179 tests; no hardware execution is implied.

## Production handler — src/hybrid_frontend.c:3281-3415
```c
3281: static long hybrid_front_sync_boost_groups_ioctl(
3282:     struct hybrid_front_file *state, unsigned int command,
3283:     unsigned long argument)
3284: {
3285:     NVOS54_PARAMETERS control;
3286:     nv_ioctl_xfer_t xfer;
3287:     void __user *user = (void __user *)argument;
3288:     void __user *user_control = user;
3289:     void __user *user_params;
3290:     NV0000_SYNC_GPU_BOOST_GROUP_INFO_PARAMS *empty = NULL;
3291:     struct hybrid_front_root *root;
3292:     NvU32 group_count[2] = { 0xffffffffU, 0xffffffffU };
3293:     NvU32 rm_status[2] = { 0xffffffffU, 0xffffffffU };
3294:     NV_STATUS transport[2] = { NV_ERR_INVALID_STATE, NV_ERR_INVALID_STATE };
3295:     unsigned int number = _IOC_NR(command);
3296:     size_t size;
3297:     long rc = 0;
3298:     int lock_rc;
3299: 
3300:     BUILD_BUG_ON(sizeof(NV0000_SYNC_GPU_BOOST_GROUP_INFO_PARAMS) != 2244);
3301:     if (state == NULL || _IOC_TYPE(command) != NV_IOCTL_MAGIC ||
3302:         _IOC_DIR(command) != (_IOC_READ | _IOC_WRITE))
3303:         return -EINVAL;
3304:     if (number == NV_ESC_RM_CONTROL) {
3305:         size = _IOC_SIZE(command);
3306:         if (size != sizeof(control))
3307:             return -EINVAL;
3308:     } else if (number == NV_ESC_IOCTL_XFER_CMD) {
3309:         if (_IOC_SIZE(command) != sizeof(xfer))
3310:             return -EINVAL;
3311:         if (copy_from_user(&xfer, user, sizeof(xfer)))
3312:             return -EFAULT;
3313:         if (xfer.cmd != NV_ESC_RM_CONTROL)
3314:             return -ENOTTY;
3315:         if (xfer.size != sizeof(control))
3316:             return -EINVAL;
3317:         user_control = (void __user *)NvP64_VALUE(xfer.ptr);
3318:         if (user_control == NULL)
3319:             return -EINVAL;
3320:         size = xfer.size;
3321:     } else {
3322:         return -ENOTTY;
3323:     }
3324:     if (copy_from_user(&control, user_control, size))
3325:         return -EFAULT;
3326:     if (control.cmd != NV0000_CTRL_CMD_SYNC_GPU_BOOST_GROUP_INFO ||
3327:         control.flags != NVOS54_FLAGS_NONE || control.hClient == 0 ||
3328:         control.hObject != control.hClient ||
3329:         control.paramsSize != sizeof(*empty) ||
3330:         NvP64_VALUE(control.params) == NULL)
3331:         return -EINVAL;
3332:     user_params = (void __user *)NvP64_VALUE(control.params);
3333: 
3334:     empty = kzalloc(sizeof(*empty), GFP_KERNEL);
3335:     if (empty == NULL) {
3336:         control.status = NV_ERR_NO_MEMORY;
3337:         rc = -ENOMEM;
3338:         goto copy_control;
3339:     }
3340: 
3341:     lock_rc = mutex_lock_interruptible(&state->transaction_lock);
3342:     if (lock_rc != 0) {
3343:         control.status = NV_ERR_OPERATING_SYSTEM;
3344:         rc = lock_rc;
3345:         goto copy_control;
3346:     }
3347:     root = hybrid_front_find_root(state, control.hClient);
3348:     if (hybrid_front_file_is_quarantined(state) || root == NULL ||
3349:         root->root.state != HYBRID_ROOT_ACTIVE ||
3350:         root->root.slot[HYBRID580_BACKEND_LEGACY].handle != control.hClient ||
3351:         root->root.slot[HYBRID580_BACKEND_OPEN].handle != control.hClient) {
3352:         control.status = NV_ERR_INVALID_OBJECT_HANDLE;
3353:         rc = -EINVAL;
3354:     } else if (state->sessions[HYBRID580_BACKEND_LEGACY] == NULL ||
3355:                state->sessions[HYBRID580_BACKEND_OPEN] == NULL) {
3356:         control.status = NV_ERR_INVALID_STATE;
3357:         rc = -EINVAL;
3358:     } else {
3359:         transport[HYBRID580_BACKEND_LEGACY] =
3360:             hybrid580_legacy_control_session_sync_boost_groups_v1(
3361:                 state->sessions[HYBRID580_BACKEND_LEGACY],
3362:                 root->root.slot[HYBRID580_BACKEND_LEGACY].handle,
3363:                 root->root.slot[HYBRID580_BACKEND_LEGACY].handle,
3364:                 NVOS54_FLAGS_NONE, &group_count[HYBRID580_BACKEND_LEGACY],
3365:                 &rm_status[HYBRID580_BACKEND_LEGACY]);
3366:         transport[HYBRID580_BACKEND_OPEN] =
3367:             hybrid580_open_control_session_sync_boost_groups_v1(
3368:                 state->sessions[HYBRID580_BACKEND_OPEN],
3369:                 root->root.slot[HYBRID580_BACKEND_OPEN].handle,
3370:                 root->root.slot[HYBRID580_BACKEND_OPEN].handle,
3371:                 NVOS54_FLAGS_NONE, &group_count[HYBRID580_BACKEND_OPEN],
3372:                 &rm_status[HYBRID580_BACKEND_OPEN]);
3373: 
3374:         if (transport[HYBRID580_BACKEND_LEGACY] != NV_OK) {
3375:             control.status = transport[HYBRID580_BACKEND_LEGACY];
3376:             rc = -EINVAL;
3377:         } else if (transport[HYBRID580_BACKEND_OPEN] != NV_OK) {
3378:             control.status = transport[HYBRID580_BACKEND_OPEN];
3379:             rc = -EINVAL;
3380:         } else if (rm_status[HYBRID580_BACKEND_LEGACY] == 0xffffffffU ||
3381:                    rm_status[HYBRID580_BACKEND_OPEN] == 0xffffffffU) {
3382:             control.status = NV_ERR_INVALID_STATE;
3383:             rc = -EINVAL;
3384:         } else if (rm_status[HYBRID580_BACKEND_LEGACY] != NV_OK) {
3385:             control.status = rm_status[HYBRID580_BACKEND_LEGACY];
3386:         } else if (rm_status[HYBRID580_BACKEND_OPEN] != NV_OK) {
3387:             control.status = rm_status[HYBRID580_BACKEND_OPEN];
3388:         } else if (group_count[HYBRID580_BACKEND_LEGACY] >
3389:                        NV0000_SYNC_GPU_BOOST_MAX_GROUPS ||
3390:                    group_count[HYBRID580_BACKEND_OPEN] >
3391:                        NV0000_SYNC_GPU_BOOST_MAX_GROUPS) {
3392:             control.status = NV_ERR_INVALID_STATE;
3393:             rc = -EINVAL;
3394:         } else if (group_count[HYBRID580_BACKEND_LEGACY] != 0 ||
3395:                    group_count[HYBRID580_BACKEND_OPEN] != 0) {
3396:             control.status = NV_ERR_NOT_SUPPORTED;
3397:         } else {
3398:             control.status = NV_OK;
3399:         }
3400:     }
3401:     mutex_unlock(&state->transaction_lock);
3402: 
3403:     /* The payload is fully zeroed and published only for a verified 0/0. */
3404:     if (rc == 0 && control.status == NV_OK &&
3405:         copy_to_user(user_params, empty, sizeof(*empty))) {
3406:         control.status = NV_ERR_INVALID_PARAM_STRUCT;
3407:         rc = -EFAULT;
3408:     }
3409: 
3410: copy_control:
3411:     if (copy_to_user(user_control, &control, sizeof(control)))
3412:         rc = -EFAULT;
3413:     kfree(empty);
3414:     return rc;
3415: }
```

## Fake backend contract — tests/test_hybrid_frontend.py:406-446
```c
406: static int sync_boost_calls[2];
407: static NV_STATUS sync_boost_transport[2]={NV_OK,NV_OK};
408: static NvU32 sync_boost_embedded[2]={NV_OK,NV_OK};
409: static NvU32 sync_boost_count[2]={0,0};
410: static bool sync_boost_no_status[2], sync_boost_no_count[2];
411: static NvHandle sync_boost_client[2], sync_boost_object[2];
412: static NvU32 sync_boost_flags[2], sync_boost_payload_size[2];
413: static NV_STATUS fake_sync_boost_groups(unsigned int backend,
414:  struct hybrid580_control_session *session, NvHandle h_client,
415:  NvHandle h_object, NvU32 flags, NvU32 *group_count,
416:  NvU32 *control_status) {
417:  assert(lock_depth==1 && session && (unsigned int)session->backend==backend);
418:  assert(group_count && control_status && h_client==h_object &&
419:         flags==NVOS54_FLAGS_NONE);
420:  ++sync_boost_calls[backend];
421:  sync_boost_client[backend]=h_client; sync_boost_object[backend]=h_object;
422:  sync_boost_flags[backend]=flags;
423:  sync_boost_payload_size[backend]=sizeof(NV0000_SYNC_GPU_BOOST_GROUP_INFO_PARAMS);
424:  *group_count=0xffffffffU;
425:  if(!sync_boost_no_status[backend])
426:   *control_status=sync_boost_embedded[backend];
427:  if(sync_boost_transport[backend]!=NV_OK ||
428:     sync_boost_embedded[backend]!=NV_OK || sync_boost_no_status[backend] ||
429:     sync_boost_no_count[backend]) return sync_boost_transport[backend];
430:  *group_count=sync_boost_count[backend];
431:  return NV_OK;
432: }
433: NV_STATUS hybrid580_legacy_control_session_sync_boost_groups_v1(
434:  struct hybrid580_control_session *session, NvHandle h_client,
435:  NvHandle h_object, NvU32 flags, NvU32 *group_count,
436:  NvU32 *control_status) {
437:  return fake_sync_boost_groups(HYBRID580_BACKEND_LEGACY,session,h_client,
438:      h_object,flags,group_count,control_status);
439: }
440: NV_STATUS hybrid580_open_control_session_sync_boost_groups_v1(
441:  struct hybrid580_control_session *session, NvHandle h_client,
442:  NvHandle h_object, NvU32 flags, NvU32 *group_count,
443:  NvU32 *control_status) {
444:  return fake_sync_boost_groups(HYBRID580_BACKEND_OPEN,session,h_client,
445:      h_object,flags,group_count,control_status);
446: }
```

## Test adapters — tests/test_hybrid_frontend.py:1669-1696
```c
1669: static long sync_boost_direct(NvHandle root_id,
1670:     NV0000_SYNC_GPU_BOOST_GROUP_INFO_PARAMS *output, NvU32 flags,
1671:     NvU32 params_size, NvU32 *status) {
1672:  NV0000_SYNC_GPU_BOOST_GROUP_INFO_PARAMS params;
1673:  memset(&params,0xa5,sizeof(params));
1674:  NVOS54_PARAMETERS control={.hClient=root_id,.hObject=root_id,
1675:    .cmd=NV0000_CTRL_CMD_SYNC_GPU_BOOST_GROUP_INFO,.flags=flags,
1676:    .params=&params,.paramsSize=params_size,.status=0xffffffffU};
1677:  long rc=hybrid_front_ioctl(&front,rm_control_cmd,(unsigned long)&control);
1678:  if(output) *output=params;
1679:  if(status) *status=control.status;
1680:  return rc;
1681: }
1682: static long sync_boost_xfer(NvHandle root_id,
1683:     NV0000_SYNC_GPU_BOOST_GROUP_INFO_PARAMS *output, NvU32 *status) {
1684:  NV0000_SYNC_GPU_BOOST_GROUP_INFO_PARAMS params;
1685:  memset(&params,0xa5,sizeof(params));
1686:  NVOS54_PARAMETERS control={.hClient=root_id,.hObject=root_id,
1687:    .cmd=NV0000_CTRL_CMD_SYNC_GPU_BOOST_GROUP_INFO,.flags=NVOS54_FLAGS_NONE,
1688:    .params=&params,.paramsSize=sizeof(params),.status=0xffffffffU};
1689:  nv_ioctl_xfer_t xfer={.cmd=NV_ESC_RM_CONTROL,.size=sizeof(control),
1690:                        .ptr=(NvP64)&control};
1691:  unsigned int command=_IOWR(NV_IOCTL_MAGIC,NV_ESC_IOCTL_XFER_CMD,nv_ioctl_xfer_t);
1692:  long rc=hybrid_front_ioctl(&front,command,(unsigned long)&xfer);
1693:  if(output) *output=params;
1694:  if(status) *status=control.status;
1695:  return rc;
1696: }
```

## RM status and transport assertions — tests/test_hybrid_frontend.py:2478-2572
```c
2478:  if(!strcmp(s,"sync-boost-groups-policy")) {
2479:   make_front(); assert(!alloc_root(false) && p21.status==NV_OK);
2480:   NvHandle root=p21.hObjectNew;
2481:   NV0000_SYNC_GPU_BOOST_GROUP_INFO_PARAMS params;
2482:   NvU32 status=0xffffffffU;
2483:   assert(sync_boost_direct(root,&params,NVOS54_FLAGS_NONE,
2484:       sizeof(params),&status)==0 && status==NV_OK);
2485:   for(size_t i=0;i<sizeof(params);i++)
2486:    assert(((const unsigned char *)&params)[i]==0);
2487:   assert(sync_boost_xfer(root,&params,&status)==0 && status==NV_OK);
2488:   for(size_t i=0;i<sizeof(params);i++)
2489:    assert(((const unsigned char *)&params)[i]==0);
2490:   assert(sync_boost_calls[HYBRID580_BACKEND_LEGACY]==2 &&
2491:          sync_boost_calls[HYBRID580_BACKEND_OPEN]==2 &&
2492:          sync_boost_client[HYBRID580_BACKEND_LEGACY]==root &&
2493:          sync_boost_client[HYBRID580_BACKEND_OPEN]==root &&
2494:          sync_boost_object[HYBRID580_BACKEND_LEGACY]==root &&
2495:          sync_boost_object[HYBRID580_BACKEND_OPEN]==root &&
2496:          sync_boost_flags[HYBRID580_BACKEND_LEGACY]==NVOS54_FLAGS_NONE &&
2497:          sync_boost_flags[HYBRID580_BACKEND_OPEN]==NVOS54_FLAGS_NONE &&
2498:          sync_boost_payload_size[HYBRID580_BACKEND_LEGACY]==2244 &&
2499:          sync_boost_payload_size[HYBRID580_BACKEND_OPEN]==2244);
2500:   front_put(); return 0;
2501:  }
2502:  if(!strcmp(s,"sync-boost-groups-nonzero")) {
2503:   make_front(); assert(!alloc_root(false) && p21.status==NV_OK);
2504:   NvHandle root=p21.hObjectNew;
2505:   NV0000_SYNC_GPU_BOOST_GROUP_INFO_PARAMS params;
2506:   NvU32 status=0xffffffffU;
2507:   for(int owner=0;owner<2;owner++) {
2508:    sync_boost_count[owner]=1;
2509:    assert(sync_boost_direct(root,&params,NVOS54_FLAGS_NONE,
2510:        sizeof(params),&status)==0 && status==NV_ERR_NOT_SUPPORTED);
2511:    for(size_t i=0;i<sizeof(params);i++)
2512:     assert(((const unsigned char *)&params)[i]==0xa5);
2513:    sync_boost_count[owner]=0;
2514:   }
2515:   assert(sync_boost_direct(root,&params,NVOS54_FLAGS_NONE,
2516:       sizeof(params),&status)==0 && status==NV_OK);
2517:   for(size_t i=0;i<sizeof(params);i++)
2518:    assert(((const unsigned char *)&params)[i]==0);
2519:   assert(sync_boost_calls[0]==3 && sync_boost_calls[1]==3);
2520:   front_put(); return 0;
2521:  }
2522:  if(!strcmp(s,"sync-boost-groups-transport-error")) {
2523:   make_front(); assert(!alloc_root(false) && p21.status==NV_OK);
2524:   NvHandle root=p21.hObjectNew;
2525:   NV0000_SYNC_GPU_BOOST_GROUP_INFO_PARAMS params;
2526:   NvU32 status=0xffffffffU;
2527:   for(int owner=0;owner<2;owner++) {
2528:    sync_boost_transport[owner]=NV_ERR_OPERATING_SYSTEM;
2529:    assert(sync_boost_direct(root,&params,NVOS54_FLAGS_NONE,
2530:        sizeof(params),&status)==-EINVAL && status==NV_ERR_OPERATING_SYSTEM);
2531:    for(size_t i=0;i<sizeof(params);i++)
2532:     assert(((const unsigned char *)&params)[i]==0xa5);
2533:    sync_boost_transport[owner]=NV_OK;
2534:   }
2535:   assert(sync_boost_calls[0]==2 && sync_boost_calls[1]==2);
2536:   front_put(); return 0;
2537:  }
2538:  if(!strcmp(s,"sync-boost-groups-rm-error")) {
2539:   make_front(); assert(!alloc_root(false) && p21.status==NV_OK);
2540:   NvHandle root=p21.hObjectNew;
2541:   NV0000_SYNC_GPU_BOOST_GROUP_INFO_PARAMS params;
2542:   NvU32 status=0xffffffffU;
2543:   for(int owner=0;owner<2;owner++) {
2544:    sync_boost_embedded[owner]=NV_ERR_NOT_SUPPORTED;
2545:    assert(sync_boost_direct(root,&params,NVOS54_FLAGS_NONE,
2546:        sizeof(params),&status)==0 && status==NV_ERR_NOT_SUPPORTED);
2547:    for(size_t i=0;i<sizeof(params);i++)
2548:     assert(((const unsigned char *)&params)[i]==0xa5);
2549:    sync_boost_embedded[owner]=NV_OK;
2550:   }
2551:   front_put(); return 0;
2552:  }
2553:  if(!strcmp(s,"sync-boost-groups-malformed-provider")) {
2554:   make_front(); assert(!alloc_root(false) && p21.status==NV_OK);
2555:   NvHandle root=p21.hObjectNew;
2556:   NV0000_SYNC_GPU_BOOST_GROUP_INFO_PARAMS params;
2557:   NvU32 status=0xffffffffU;
2558:   sync_boost_no_status[0]=true;
2559:   assert(sync_boost_direct(root,&params,NVOS54_FLAGS_NONE,
2560:       sizeof(params),&status)==-EINVAL && status==NV_ERR_INVALID_STATE);
2561:   sync_boost_no_status[0]=false;
2562:   sync_boost_no_count[1]=true;
2563:   assert(sync_boost_direct(root,&params,NVOS54_FLAGS_NONE,
2564:       sizeof(params),&status)==-EINVAL && status==NV_ERR_INVALID_STATE);
2565:   sync_boost_no_count[1]=false;
2566:   sync_boost_count[0]=NV0000_SYNC_GPU_BOOST_MAX_GROUPS+1;
2567:   assert(sync_boost_direct(root,&params,NVOS54_FLAGS_NONE,
2568:       sizeof(params),&status)==-EINVAL && status==NV_ERR_INVALID_STATE);
2569:   for(size_t i=0;i<sizeof(params);i++)
2570:    assert(((const unsigned char *)&params)[i]==0xa5);
2571:   front_put(); return 0;
2572:  }
```
