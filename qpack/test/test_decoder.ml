(*
 *  #[test]
 *  fn decoder_block_ack() {
 *      let mut table = build_table();

 *      let field = HeaderField::new("foo", "bar");
 *      check_encode_field_table(
 *          &mut table,
 *          &[],
 *          &[field.clone(), field.with_value("quxx")],
 *          2,
 *          &|_, _| {},
 *      );

 *      let mut buf = vec![];

 *      HeaderAck(2).encode(&mut buf);
 *      let mut cur = Cursor::new(&buf);
 *      assert_eq!(
 *          parse_instruction(&mut cur),
 *          Ok(Some(Instruction::Untrack(2)))
 *      );

 *      let mut cur = Cursor::new(&buf);
 *      assert_eq!(on_decoder_recv(&mut table, &mut cur), Ok(()),);

 *      let mut cur = Cursor::new(&buf);
 *      assert_eq!(
 *          on_decoder_recv(&mut table, &mut cur),
 *          Err(Error::Insertion(DynamicTableError::UnknownStreamId(2)))
 *      );
 *  }

 *  #[test]
 *  fn decoder_stream_cacnceled() {
 *      let mut table = build_table();

 *      let field = HeaderField::new("foo", "bar");
 *      check_encode_field_table(
 *          &mut table,
 *          &[],
 *          &[field.clone(), field.with_value("quxx")],
 *          2,
 *          &|_, _| {},
 *      );

 *      let mut buf = vec![];

 *      StreamCancel(2).encode(&mut buf);
 *      let mut cur = Cursor::new(&buf);
 *      assert_eq!(
 *          parse_instruction(&mut cur),
 *          Ok(Some(Instruction::Untrack(2)))
 *      );
 *  }

 *  #[test]
 *  fn decoder_accept_trucated() {
 *      let mut buf = vec![];
 *      StreamCancel(2321).encode(&mut buf);

 *      let mut cur = Cursor::new(&buf[..2]); // trucated prefix_int
 *      assert_eq!(parse_instruction(&mut cur), Ok(None));

 *      let mut cur = Cursor::new(&buf);
 *      assert_eq!(
 *          parse_instruction(&mut cur),
 *          Ok(Some(Instruction::Untrack(2321)))
 *      );
 *  }

 *  #[test]
 *  fn decoder_unknown_stream() {
 *      let mut table = build_table();

 *      check_encode_field_table(
 *          &mut table,
 *          &[],
 *          &[HeaderField::new("foo", "bar")],
 *          2,
 *          &|_, _| {},
 *      );

 *      let mut buf = vec![];
 *      StreamCancel(4).encode(&mut buf);

 *      let mut cur = Cursor::new(&buf);
 *      assert_eq!(
 *          on_decoder_recv(&mut table, &mut cur),
 *          Err(Error::Insertion(DynamicTableError::UnknownStreamId(4)))
 *      );
 *  }

 *  #[test]
 *  fn insert_count() {
 *      let mut buf = vec![];
 *      InsertCountIncrement(4).encode(&mut buf);

 *      let mut cur = Cursor::new(&buf);
 *      assert_eq!(
 *          parse_instruction(&mut cur),
 *          Ok(Some(Instruction::ReceivedRefIncrement(4)))
 *      );

 *      let mut cur = Cursor::new(&buf);
 *      assert_eq!(on_decoder_recv(&mut build_table(), &mut cur), Ok(()));
 *  }
 *)
