package net.java.web3.striple;

import junit.framework.TestCase;

// TODO storage to seakabe byte array buffer to emulate file
public class Storage extends TestCase {
/*
#[cfg(test)]
pub mod test {
  use striple::Striple;
//  use striple::copy_builder_id;
  use striple::ref_builder_id_copy;
  use striple::StripleIf;
  use striple::AsStriple;
  use striple::StripleKind;
  use striple::NoKind;
  use striple::IDDerivation;
  use striple::SignatureScheme;
  use storage::{NoCypher,write_striple,read_striple,write_striple_file,FileStripleIterator,initNoCypher};
  use striple::test::{sampleStriple1,sampleStriple2,random_bytes,compare_striple};
  use std::io::{Write,Read,Cursor,Seek,SeekFrom};
  use std::marker::PhantomData;
  use std::slice::Iter;
  use std::io::Result as IOResult;

  #[test]
  fn test_striple_enc_dec () {
    let mut tmpvec : Vec<u8> = Vec::new();
    let mut buf = Cursor::new(tmpvec);
    let striple1 = sampleStriple1();
    let striple2 = sampleStriple2();
    let pkey = random_bytes(18);
    debug!("{:?}", buf);
    let mut wr = write_striple(&NoCypher, &striple1, None, &mut buf);
    debug!("{:?}", buf);
    assert!(wr.is_ok());
    wr = write_striple(&NoCypher, &striple2,Some(&pkey), &mut buf);
    assert!(wr.is_ok());

    assert!(buf.seek(SeekFrom::Start(0)).is_ok());
    
    debug!("{:?}", buf);
    let readstriple1  = read_striple::<_,NoKind,Striple<NoKind>,_,_>(&NoCypher, &mut buf, ref_builder_id_copy);
    debug!("{:?}", readstriple1);
    assert!(readstriple1.is_ok());
    assert!(compare_striple(&readstriple1.unwrap().0,&striple1));
    let readstriple2res = read_striple::<_,NoKind,Striple<NoKind>,_,_>(&NoCypher, &mut buf, ref_builder_id_copy);
    debug!("{:?}", readstriple2res);
    assert!(readstriple2res.is_ok());
    let (readstriple2, readpkey) = readstriple2res.unwrap();
    assert!(compare_striple(&striple2,&readstriple2));
    assert!(readpkey.unwrap() == pkey);
  }

  #[test]
  fn test_striple_enc_dec_file () {
    let mut tmpvec : Vec<u8> = Vec::new();
    let mut buf = Cursor::new(tmpvec);
    let striple1 = sampleStriple1();
    let striple2 = sampleStriple2();
    let pkey = random_bytes(18);
    let mut vecst : Vec<(&Striple<NoKind>,Option<&[u8]>)> = Vec::new();
    vecst.push((&striple1,None));
    vecst.push((&striple2,Some(&pkey[..])));
    
    let wr = write_striple_file(&NoCypher, &mut vecst.iter().map(|p|(p.0,p.1)), &mut buf);
    assert!(wr.is_ok());
    let mut rit : IOResult<FileStripleIterator<NoKind,Striple<NoKind>,_,_,_>> = FileStripleIterator::init(buf, ref_builder_id_copy, initNoCypher); 
    assert!(rit.is_ok());
    let mut it = rit.unwrap();
    let st1 = it.next();
    assert!(st1.is_some());
    assert!(compare_striple(&st1.unwrap().0,&striple1));
    let st2 = it.next();
    assert!(st2.is_some());
    let (readstriple2, readpkey) = st2.unwrap();
    assert!(compare_striple(&striple2,&readstriple2));
    assert!(readpkey.unwrap() == pkey);
    let st3 = it.next();
    assert!(st3.is_none());
  }
*/

}
