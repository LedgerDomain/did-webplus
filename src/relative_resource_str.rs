use crate::{Error, Fragment};

#[derive(Debug, Eq, Hash, PartialEq, pneutype::PneuStr)]
#[pneu_str(deserialize, serialize, str_field = "1")]
#[repr(transparent)]
pub struct RelativeResourceStr<F: 'static + Fragment + ?Sized>(std::marker::PhantomData<F>, str);

impl<F: 'static + Fragment + ?Sized> RelativeResourceStr<F> {
    pub fn fragment(&self) -> &F {
        F::new_ref(self.1.strip_prefix('#').unwrap()).unwrap()
    }
}

impl<F: 'static + Fragment + ?Sized> pneutype::Validate for RelativeResourceStr<F> {
    type Data = str;
    type Error = Error;
    fn validate(data: &Self::Data) -> Result<(), Self::Error> {
        if !data.starts_with('#') {
            return Err(Error::Malformed("RelativeResource must start with '#'"));
        }
        let fragment = data.strip_prefix('#').unwrap();
        F::validate(fragment)
            .map_err(|_| Error::Malformed("RelativeResource fragment is malformed"))?;
        Ok(())
    }
}
